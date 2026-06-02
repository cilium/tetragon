// Copyright © 2015-2020 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

package yara

/*
#include <stdlib.h>
#include <yara.h>

// rules_table is part of a union and as such not reachable from go code.
static YR_RULE* find_rule(YR_RULES* r, unsigned int rule_idx) {
	return &r->rules_table[rule_idx];
}
*/
import "C"
import (
	"reflect"
	"runtime"
	"unsafe"
)

// ScanContext contains the data passed to the ScanCallback methods.
//
// Since this type contains a C pointer to a YR_SCAN_CONTEXT structure
// that may be automatically freed, it should not be copied.
type ScanContext struct {
	cptr *C.YR_SCAN_CONTEXT
}

// ScanCallback is a placeholder for different interfaces that may be
// implemented by the callback object that is passed to the
// (*Rules).ScanXxxx and (*Scanner).ScanXxxx methods.
//
// The RuleMatching method corresponds to YARA's
// CALLBACK_MSG_RULE_MATCHING message.
type ScanCallback interface {
	RuleMatching(*ScanContext, *Rule) (bool, error)
}

// ScanCallbackNoMatch is used to record rules that did not match
// during a scan. The RuleNotMatching method corresponds to YARA's
// CALLBACK_MSG_RULE_NOT_MATCHING mssage.
type ScanCallbackNoMatch interface {
	RuleNotMatching(*ScanContext, *Rule) (bool, error)
}

// ScanCallbackFinished is used to signal that a scan has finished.
// The ScanFinished method corresponds to YARA's
// CALLBACK_MSG_SCAN_FINISHED message.
type ScanCallbackFinished interface {
	ScanFinished(*ScanContext) (bool, error)
}

// ScanCallbackModuleImport is used to provide data to a YARA module.
// The ImportModule method corresponds to YARA's
// CALLBACK_MSG_IMPORT_MODULE message.
type ScanCallbackModuleImport interface {
	ImportModule(*ScanContext, string) ([]byte, bool, error)
}

// ScanCallbackModuleImportFinished can be used to free resources that
// have been used in the ScanCallbackModuleImport implementation. The
// ModuleImported method corresponds to YARA's
// CALLBACK_MSG_MODULE_IMPORTED message.
type ScanCallbackModuleImportFinished interface {
	ModuleImported(*ScanContext, *Object) (bool, error)
}

// ScanCallbackConsoleLog can be used to implement custom functions
// to handle the console.log feature introduced in YARA 4.2.
type ScanCallbackConsoleLog interface {
	ConsoleLog(*ScanContext, string)
}

// ScanCallbackTooManyMatches can be used to receive information about
// strings that match too many times.
type ScanCallbackTooManyMatches interface {
	TooManyMatches(*ScanContext, *Rule, string) (bool, error)
}

// scanCallbackContainer is used by to pass a ScanCallback (and
// associated data) between ScanXxx methods and scanCallbackFunc(). It
// stores the public callback interface and a list of malloc()'d C
// pointers.
type scanCallbackContainer struct {
	ScanCallback
	rules *Rules
	cdata []unsafe.Pointer
}

// makeScanCallbackContainer sets up a scanCallbackContainer with a
// finalizer method that that frees any stored C pointers when the
// container is garbage-collected.
func makeScanCallbackContainer(sc ScanCallback, r *Rules) *scanCallbackContainer {
	c := &scanCallbackContainer{sc, r, nil}
	runtime.SetFinalizer(c, (*scanCallbackContainer).finalize)
	return c
}

// addCPointer adds a C pointer that can later be freed using free().
func (c *scanCallbackContainer) addCPointer(p unsafe.Pointer) { c.cdata = append(c.cdata, p) }

// finalize frees stored C pointers
func (c *scanCallbackContainer) finalize() {
	for _, p := range c.cdata {
		C.free(p)
	}
	c.cdata = nil
	runtime.SetFinalizer(c, nil)
}

//export scanCallbackFunc
func scanCallbackFunc(ctx *C.YR_SCAN_CONTEXT, message C.int, messageData, userData unsafe.Pointer) C.int {
	cbc, ok := cgoHandle(*(*uintptr)(userData)).Value().(*scanCallbackContainer)
	s := &ScanContext{cptr: ctx}
	if !ok {
		return C.CALLBACK_ERROR
	}
	if cbc.ScanCallback == nil {
		return C.CALLBACK_CONTINUE
	}
	var abort bool
	var err error
	switch message {
	case C.CALLBACK_MSG_RULE_MATCHING:
		abort, err = cbc.ScanCallback.RuleMatching(s, &Rule{(*C.YR_RULE)(messageData), cbc.rules})
	case C.CALLBACK_MSG_RULE_NOT_MATCHING:
		if c, ok := cbc.ScanCallback.(ScanCallbackNoMatch); ok {
			abort, err = c.RuleNotMatching(s, &Rule{(*C.YR_RULE)(messageData), cbc.rules})
		}
	case C.CALLBACK_MSG_SCAN_FINISHED:
		if c, ok := cbc.ScanCallback.(ScanCallbackFinished); ok {
			abort, err = c.ScanFinished(s)
		}
	case C.CALLBACK_MSG_IMPORT_MODULE:
		if c, ok := cbc.ScanCallback.(ScanCallbackModuleImport); ok {
			mi := (*C.YR_MODULE_IMPORT)(messageData)
			var buf []byte
			if buf, abort, err = c.ImportModule(s, C.GoString(mi.module_name)); len(buf) == 0 {
				break
			}
			cbuf := C.calloc(1, C.size_t(len(buf)))
			outbuf := make([]byte, 0)
			hdr := (*reflect.SliceHeader)(unsafe.Pointer(&outbuf))
			hdr.Data, hdr.Len = uintptr(cbuf), len(buf)
			copy(outbuf, buf)
			mi.module_data, mi.module_data_size = unsafe.Pointer(&outbuf[0]), C.size_t(len(outbuf))
			cbc.addCPointer(cbuf)
		}
	case C.CALLBACK_MSG_MODULE_IMPORTED:
		if c, ok := cbc.ScanCallback.(ScanCallbackModuleImportFinished); ok {
			abort, err = c.ModuleImported(s, &Object{(*C.YR_OBJECT)(messageData)})
		}
	case C.CALLBACK_MSG_CONSOLE_LOG:
		if c, ok := cbc.ScanCallback.(ScanCallbackConsoleLog); ok {
			c.ConsoleLog(s, C.GoString((*C.char)(messageData)))
		}
	case C.CALLBACK_MSG_TOO_MANY_MATCHES:
		if c, ok := cbc.ScanCallback.(ScanCallbackTooManyMatches); ok {
			yrString := String{(*C.YR_STRING)(messageData), cbc.rules}
			rule := &Rule{
				cptr:  C.find_rule(cbc.rules.cptr, yrString.cptr.rule_idx),
				owner: cbc.rules,
			}
			abort, err = c.TooManyMatches(s, rule, yrString.Identifier())
		}
	}

	if err != nil {
		return C.CALLBACK_ERROR
	}
	if abort {
		return C.CALLBACK_ABORT
	}
	return C.CALLBACK_CONTINUE
}

// MatchRules is used to collect matches that are returned by the
// simple (*Rules).Scan* methods.
type MatchRules []MatchRule

// RuleMatching implements the ScanCallbackMatch interface for
// MatchRules.
func (mr *MatchRules) RuleMatching(sc *ScanContext, r *Rule) (abort bool, err error) {
	*mr = append(*mr, MatchRule{
		Rule:      r.Identifier(),
		Namespace: r.Namespace(),
		Tags:      r.Tags(),
		Metas:     r.Metas(),
		Strings:   r.getMatchStrings(sc),
	})
	return
}
