// Copyright © 2015-2020 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

package yara

/*
#include <yara.h>
#include "compat.h"

int scanCallbackFunc(YR_SCAN_CONTEXT*, int, void*, void*);
*/
import "C"
import (
	"errors"
	"runtime"
	"time"
	"unsafe"
)

// Scanner contains a YARA scanner (YR_SCANNER). The main difference
// to Rules (YR_RULES) is that it is possible to set variables in a
// thread-safe manner (cf.
// https://github.com/VirusTotal/yara/issues/350).
//
// Since this type contains a C pointer to a YR_SCANNER structure that
// may be automatically freed, it should not be copied.
type Scanner struct {
	cptr *C.YR_SCANNER
	// The Scanner struct has to hold a pointer to the rules
	// it wraps, as otherwise it may be be garbage collected.
	rules *Rules
	// Current callback object, set by SetCallback
	Callback ScanCallback
	// Scan flags are set just before scanning.
	flags ScanFlags
	// userData stores handle of the currently set callback object. It is
	// allocated using malloc so that the GC does not mess with it.
	userData *cgoHandle
}

// Creates a new error that includes information a about the rule
// causing the error.
func (s *Scanner) newScanError(code C.int) error {
	if code == C.ERROR_SUCCESS {
		return nil
	}
	err := Error{Code: int(code)}
	if rule := s.GetLastErrorRule(); rule != nil {
		err.RuleIdentifier = rule.Identifier()
		err.Namespace = rule.Namespace()
	}
	if str := s.GetLastErrorString(); str != nil {
		err.StringIdentifier = str.Identifier()
	}
	return err
}

// NewScanner creates a YARA scanner.
func NewScanner(r *Rules) (*Scanner, error) {
	var yrScanner *C.YR_SCANNER
	if err := newError(C.yr_scanner_create(r.cptr, &yrScanner)); err != nil {
		return nil, err
	}
	s := &Scanner{cptr: yrScanner, rules: r, userData: (*cgoHandle)(C.malloc(C.size_t(unsafe.Sizeof(cgoHandle(0)))))}
	*s.userData = 0
	runtime.SetFinalizer(s, (*Scanner).Destroy)
	return s, nil
}

// Destroy destroys the YARA data structure representing a scanner.
//
// It should not be necessary to call this method directly.
func (s *Scanner) Destroy() {
	if s.cptr != nil {
		C.yr_scanner_destroy(s.cptr)
		s.cptr = nil
	}
	if s.userData != nil {
		if *s.userData != 0 {
			s.userData.Delete()
		}
		C.free(unsafe.Pointer(s.userData))
		s.userData = nil
	}
	runtime.SetFinalizer(s, nil)
}

// DefineVariable defines a named variable for use by the scanner.
// Boolean, int64, float64, and string types are supported.
func (s *Scanner) DefineVariable(identifier string, value interface{}) (err error) {
	cid := C.CString(identifier)
	defer C.free(unsafe.Pointer(cid))
	switch value.(type) {
	case bool:
		var v int
		if value.(bool) {
			v = 1
		}
		err = newError(C.yr_scanner_define_boolean_variable(
			s.cptr, cid, C.int(v)))
	case int, int8, int16, int32, int64, uint, uint8, uint32, uint64:
		value := toint64(value)
		err = newError(C.yr_scanner_define_integer_variable(
			s.cptr, cid, C.int64_t(value)))
	case float64:
		err = newError(C.yr_scanner_define_float_variable(
			s.cptr, cid, C.double(value.(float64))))
	case string:
		cvalue := C.CString(value.(string))
		defer C.free(unsafe.Pointer(cvalue))
		err = newError(C.yr_scanner_define_string_variable(
			s.cptr, cid, cvalue))
	default:
		err = errors.New("wrong value type passed to DefineVariable; bool, int64, float64, string are accepted")
	}
	runtime.KeepAlive(s)
	return
}

// SetFlags sets flags for the scanner.
func (s *Scanner) SetFlags(flags ScanFlags) *Scanner {
	s.flags = flags
	return s
}

// SetTimeout sets a timeout for the scanner.
func (s *Scanner) SetTimeout(timeout time.Duration) *Scanner {
	C.yr_scanner_set_timeout(s.cptr, C.int(timeout/time.Second))
	return s
}

// SetCallback sets a callback object for the scanner. For every event
// emitted by libyara during subsequent scan, the appropriate method
// on the ScanCallback object is called.
//
// For the common case where only a list of matched rules is relevant,
// setting a callback object is not necessary.
func (s *Scanner) SetCallback(cb ScanCallback) *Scanner {
	s.Callback = cb
	return s
}

// putCallbackData stores the scanner's callback object in
// a cgoHandle. If no callback object has been
// set, it is initialized with the pointer to an empty ScanRules
// object. The handle must be deleted by the calling ScanXxxx function.
func (s *Scanner) putCallbackData() {
	if _, ok := s.Callback.(ScanCallback); !ok {
		s.Callback = &MatchRules{}
	}
	if *s.userData != 0 {
		s.userData.Delete()
		*s.userData = 0
	}
	*s.userData = cgoNewHandle(makeScanCallbackContainer(s.Callback, s.rules))
	C.yr_scanner_set_callback(s.cptr, C.YR_CALLBACK_FUNC(C.scanCallbackFunc), unsafe.Pointer(s.userData))
}

// ScanMem scans an in-memory buffer using the scanner.
//
// If no callback object has been set for the scanner using
// SetCAllback, it is initialized with an empty MatchRules object.
func (s *Scanner) ScanMem(buf []byte) (err error) {
	var ptr *C.uint8_t
	if len(buf) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&(buf[0])))
	}
	s.putCallbackData()
	// SCAN_FLAGS_NO_TRYCATCH disables the YARA's exception handler that
	// captures segfaults. Capturing these exceptions only makes sense
	// while scanning memory-mapped files. When scanning in-memory data
	// the excepton-handling mechanism doesn't have any benefit and only
	// causes trouble, as it can interfere with golang's ability to detect
	// null-pointer dereferences and panic accordingly.
	C.yr_scanner_set_flags(
		s.cptr,
		s.flags.withReportFlags(s.Callback)|C.SCAN_FLAGS_NO_TRYCATCH)
	err = s.newScanError(C.yr_scanner_scan_mem(
		s.cptr,
		ptr,
		C.size_t(len(buf))))
	runtime.KeepAlive(s)
	runtime.KeepAlive(buf)
	return
}

// ScanFile scans a file using the scanner.
//
// If no callback object has been set for the scanner using
// SetCAllback, it is initialized with an empty MatchRules object.
//
// Note that the filename is passed as-is to the YARA library and may
// not be processed in a sensible way. It is recommended to avoid this
// function and to obtain an os.File handle f using os.Open() and use
// ScanFileDescriptor(f.Fd()) instead.
func (s *Scanner) ScanFile(filename string) (err error) {
	cfilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cfilename))
	s.putCallbackData()
	C.yr_scanner_set_flags(s.cptr, s.flags.withReportFlags(s.Callback))
	err = s.newScanError(C.yr_scanner_scan_file(
		s.cptr,
		cfilename,
	))
	runtime.KeepAlive(s)
	return
}

// ScanFileDescriptor scans a file using the scanner.
//
// If no callback object has been set for the scanner using
// SetCAllback, it is initialized with an empty MatchRules object.
func (s *Scanner) ScanFileDescriptor(fd uintptr) (err error) {
	s.putCallbackData()
	C.yr_scanner_set_flags(s.cptr, s.flags.withReportFlags(s.Callback))
	err = s.newScanError(C._yr_scanner_scan_fd(
		s.cptr,
		C.int(fd),
	))
	runtime.KeepAlive(s)
	return
}

// ScanProc scans a live process using the scanner.
//
// If no callback object has been set for the scanner using
// SetCAllback, it is initialized with an empty MatchRules object.
func (s *Scanner) ScanProc(pid int) (err error) {
	s.putCallbackData()
	C.yr_scanner_set_flags(s.cptr, s.flags.withReportFlags(s.Callback))
	err = s.newScanError(C.yr_scanner_scan_proc(
		s.cptr,
		C.int(pid),
	))
	runtime.KeepAlive(s)
	return
}

// ScanMemBlocks scans over a MemoryBlockIterator using the scanner.
//
// If no callback object has been set for the scanner using
// SetCallback, it is initialized with an empty MatchRules object.
func (s *Scanner) ScanMemBlocks(mbi MemoryBlockIterator) (err error) {
	c := makeMemoryBlockIteratorContainer(mbi)
	defer c.free()
	cmbi := makeCMemoryBlockIterator(c)
	defer C.free(cmbi.context)
	defer ((*cgoHandle)(cmbi.context)).Delete()
	s.putCallbackData()
	C.yr_scanner_set_flags(s.cptr, s.flags.withReportFlags(s.Callback)|C.SCAN_FLAGS_NO_TRYCATCH)
	err = s.newScanError(C.yr_scanner_scan_mem_blocks(
		s.cptr,
		cmbi,
	))
	runtime.KeepAlive(s)
	runtime.KeepAlive(mbi)
	runtime.KeepAlive(cmbi)
	return
}

// GetLastErrorRule returns the Rule which caused the last error.
//
// The result is nil, if scanner returned no rule
func (s *Scanner) GetLastErrorRule() (r *Rule) {
	ptr := C.yr_scanner_last_error_rule(s.cptr)
	if ptr != nil {
		r = &Rule{ptr, s.rules}
	}
	runtime.KeepAlive(s)
	return
}

// GetLastErrorString returns the String which caused the last error.
//
// The result is nil, if scanner returned no string
func (s *Scanner) GetLastErrorString() (r *String) {
	ptr := C.yr_scanner_last_error_string(s.cptr)
	if ptr != nil {
		r = &String{ptr, s.rules}
	}
	runtime.KeepAlive(s)
	return
}

type RuleProfilingInfo struct {
	Rule
	Cost uint64
}

// GetProfilingInfo retrieves profiling information from the Scanner.
func (s *Scanner) GetProfilingInfo() (rpis []RuleProfilingInfo) {
	rpi := C.yr_scanner_get_profiling_info(s.cptr)
	defer C.yr_free(unsafe.Pointer(rpi))
	for ; rpi.rule != nil; rpi = (*C.YR_RULE_PROFILING_INFO)(unsafe.Pointer(uintptr(unsafe.Pointer(rpi)) + unsafe.Sizeof(*rpi))) {
		rpis = append(rpis, RuleProfilingInfo{Rule{rpi.rule, s.rules}, uint64(rpi.cost)})
	}
	runtime.KeepAlive(s)
	return
}

// ResetProfilingInfo resets the Scanner's profiling information
func (s *Scanner) ResetProfilingInfo() {
	C.yr_scanner_reset_profiling_info(s.cptr)
	runtime.KeepAlive(s)
}
