// Copyright © 2015-2020 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

package yara

/*
#include <yara.h>
#include "compat.h"

size_t streamRead(void* ptr, size_t size, size_t nmemb, void* user_data);
size_t streamWrite(void* ptr, size_t size, size_t nmemb, void* user_data);

int scanCallbackFunc(YR_SCAN_CONTEXT*, int, void*, void*);
*/
import "C"
import (
	"errors"
	"io"
	"runtime"
	"time"
	"unsafe"
)

// Rules contains a compiled YARA ruleset.
//
// Since this type contains a C pointer to a YR_RULES structure that
// may be automatically freed, it should not be copied.
type Rules struct{ cptr *C.YR_RULES }

// A MatchRule represents a rule successfully matched against a block
// of data.
type MatchRule struct {
	Rule      string
	Namespace string
	Tags      []string
	Metas     []Meta
	Strings   []MatchString
}

// A MatchString represents a string declared and matched in a rule.
type MatchString struct {
	Name   string
	Base   uint64
	Offset uint64
	Data   []byte
	XorKey uint8
}

// ScanFlags are used to tweak the behavior of Scan* functions.
type ScanFlags int

const (
	// ScanFlagsFastMode avoids multiple matches of the same string
	// when not necessary.
	ScanFlagsFastMode = C.SCAN_FLAGS_FAST_MODE
	// ScanFlagsProcessMemory causes the scanned data to be
	// interpreted like live, in-prcess memory rather than an on-disk
	// file.
	ScanFlagsProcessMemory = C.SCAN_FLAGS_PROCESS_MEMORY
)

func (sf ScanFlags) withReportFlags(sc ScanCallback) (i C.int) {
	i = C.int(sf) | C.SCAN_FLAGS_REPORT_RULES_MATCHING
	if _, ok := sc.(ScanCallbackNoMatch); ok {
		i |= C.SCAN_FLAGS_REPORT_RULES_NOT_MATCHING
	}
	return
}

// ScanMem scans an in-memory buffer using the ruleset.
// For every event emitted by libyara, the corresponding method on the
// ScanCallback object is called.
func (r *Rules) ScanMem(buf []byte, flags ScanFlags, timeout time.Duration, cb ScanCallback) (err error) {
	var ptr *C.uint8_t
	if len(buf) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&(buf[0])))
	}
	userData := cgoNewHandle(makeScanCallbackContainer(cb, r))
	defer userData.Delete()
	err = newError(C.yr_rules_scan_mem(
		r.cptr,
		ptr,
		C.size_t(len(buf)),
		flags.withReportFlags(cb),
		C.YR_CALLBACK_FUNC(C.scanCallbackFunc),
		unsafe.Pointer(&userData),
		C.int(timeout/time.Second)))
	runtime.KeepAlive(r)
	runtime.KeepAlive(buf)
	return
}

// ScanFile scans a file using the ruleset. For every
// event emitted by libyara, the corresponding method on the
// ScanCallback object is called.
//
// Note that the filename is passed as-is to the YARA library and may
// not be processed in a sensible way. It is recommended to avoid this
// function and to obtain an os.File handle f using os.Open() and use
// ScanFileDescriptor(f.Fd(), …) instead.
func (r *Rules) ScanFile(filename string, flags ScanFlags, timeout time.Duration, cb ScanCallback) (err error) {
	cfilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cfilename))
	userData := cgoNewHandle(makeScanCallbackContainer(cb, r))
	defer userData.Delete()
	err = newError(C.yr_rules_scan_file(
		r.cptr,
		cfilename,
		flags.withReportFlags(cb),
		C.YR_CALLBACK_FUNC(C.scanCallbackFunc),
		unsafe.Pointer(&userData),
		C.int(timeout/time.Second)))
	runtime.KeepAlive(r)
	return
}

// ScanFileDescriptor scans a file using the ruleset. For every event
// emitted by libyara, the corresponding method on the ScanCallback
// object is called.
func (r *Rules) ScanFileDescriptor(fd uintptr, flags ScanFlags, timeout time.Duration, cb ScanCallback) (err error) {
	userData := cgoNewHandle(makeScanCallbackContainer(cb, r))
	defer userData.Delete()
	err = newError(C._yr_rules_scan_fd(
		r.cptr,
		C.int(fd),
		flags.withReportFlags(cb),
		C.YR_CALLBACK_FUNC(C.scanCallbackFunc),
		unsafe.Pointer(&userData),
		C.int(timeout/time.Second)))
	runtime.KeepAlive(r)
	return
}

// ScanProc scans a live process using the ruleset.  For
// every event emitted by libyara, the corresponding method on the
// ScanCallback object is called.
func (r *Rules) ScanProc(pid int, flags ScanFlags, timeout time.Duration, cb ScanCallback) (err error) {
	userData := cgoNewHandle(makeScanCallbackContainer(cb, r))
	defer userData.Delete()
	err = newError(C.yr_rules_scan_proc(
		r.cptr,
		C.int(pid),
		flags.withReportFlags(cb),
		C.YR_CALLBACK_FUNC(C.scanCallbackFunc),
		unsafe.Pointer(&userData),
		C.int(timeout/time.Second)))
	runtime.KeepAlive(r)
	return
}

// ScanMemBlocks scans over a MemoryBlockIterator using the ruleset.
// For every event emitted by libyara, the corresponding method on the
// ScanCallback object is called.
func (r *Rules) ScanMemBlocks(mbi MemoryBlockIterator, flags ScanFlags, timeout time.Duration, cb ScanCallback) (err error) {
	c := makeMemoryBlockIteratorContainer(mbi)
	defer c.free()
	cmbi := makeCMemoryBlockIterator(c)
	defer C.free(cmbi.context)
	defer ((*cgoHandle)(cmbi.context)).Delete()
	userData := cgoNewHandle(makeScanCallbackContainer(cb, r))
	defer userData.Delete()
	err = newError(C.yr_rules_scan_mem_blocks(
		r.cptr,
		cmbi,
		flags.withReportFlags(cb)|C.SCAN_FLAGS_NO_TRYCATCH,
		C.YR_CALLBACK_FUNC(C.scanCallbackFunc),
		unsafe.Pointer(&userData),
		C.int(timeout/time.Second)))
	runtime.KeepAlive(r)
	runtime.KeepAlive(mbi)
	runtime.KeepAlive(cmbi)
	return
}

// Save writes a compiled ruleset to filename.
func (r *Rules) Save(filename string) (err error) {
	cfilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cfilename))
	err = newError(C.yr_rules_save(r.cptr, cfilename))
	runtime.KeepAlive(r)
	return
}

// LoadRules retrieves a compiled ruleset from filename.
func LoadRules(filename string) (*Rules, error) {
	cfilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cfilename))
	r := &Rules{}
	if err := newError(C.yr_rules_load(cfilename, &(r.cptr))); err != nil {
		return nil, err
	}
	runtime.SetFinalizer(r, (*Rules).Destroy)
	return r, nil
}

// Write writes a compiled ruleset to an io.Writer.
func (r *Rules) Write(wr io.Writer) (err error) {
	userData := (*cgoHandle)(C.malloc(C.size_t(unsafe.Sizeof(cgoHandle(0)))))
	*userData = cgoNewHandle(wr)

	stream := C.YR_STREAM{
		write:     C.YR_STREAM_WRITE_FUNC(C.streamWrite),
		user_data: unsafe.Pointer(userData),
	}
	err = newError(C.yr_rules_save_stream(r.cptr, &stream))

	runtime.KeepAlive(r)
	userData.Delete()
	C.free(unsafe.Pointer(userData))
	return
}

// ReadRules retrieves a compiled ruleset from an io.Reader.
func ReadRules(rd io.Reader) (*Rules, error) {
	userData := (*cgoHandle)(C.malloc(C.size_t(unsafe.Sizeof(cgoHandle(0)))))
	*userData = cgoNewHandle(rd)

	stream := C.YR_STREAM{
		read:      C.YR_STREAM_READ_FUNC(C.streamRead),
		user_data: unsafe.Pointer(userData),
	}
	r := &Rules{}
	if err := newError(C.yr_rules_load_stream(&stream, &(r.cptr))); err != nil {
		return nil, err
	}

	runtime.SetFinalizer(r, (*Rules).Destroy)
	userData.Delete()
	C.free(unsafe.Pointer(userData))
	return r, nil
}

// Destroy destroys the YARA data structure representing a ruleset.
//
// It should not be necessary to call this method directly.
func (r *Rules) Destroy() {
	if r.cptr != nil {
		C.yr_rules_destroy(r.cptr)
		r.cptr = nil
	}
	runtime.SetFinalizer(r, nil)
}

// DefineVariable defines a named variable for use by the compiler.
// Boolean, int64, float64, and string types are supported.
func (r *Rules) DefineVariable(identifier string, value interface{}) (err error) {
	cid := C.CString(identifier)
	defer C.free(unsafe.Pointer(cid))
	switch value.(type) {
	case bool:
		var v int
		if value.(bool) {
			v = 1
		}
		err = newError(C.yr_rules_define_boolean_variable(
			r.cptr, cid, C.int(v)))
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		value := toint64(value)
		err = newError(C.yr_rules_define_integer_variable(
			r.cptr, cid, C.int64_t(value)))
	case float64:
		err = newError(C.yr_rules_define_float_variable(
			r.cptr, cid, C.double(value.(float64))))
	case string:
		cvalue := C.CString(value.(string))
		defer C.free(unsafe.Pointer(cvalue))
		err = newError(C.yr_rules_define_string_variable(
			r.cptr, cid, cvalue))
	default:
		err = errors.New("wrong value type passed to DefineVariable; bool, int64, float64, string are accepted")
	}
	runtime.KeepAlive(r)
	return
}
