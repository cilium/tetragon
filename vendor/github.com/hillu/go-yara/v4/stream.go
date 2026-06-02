// Copyright © 2015-2020 Hilko Bengen <bengen@hilluzination.de>
// All rights reserved.
//
// Use of this source code is governed by the license that can be
// found in the LICENSE file.

package yara

import (
	"io"
	"reflect"
	"unsafe"
)

// #include <string.h>
import "C"

//export streamRead
func streamRead(ptr unsafe.Pointer, size, nmemb C.size_t, userData unsafe.Pointer) C.size_t {
	if size == 0 || nmemb == 0 {
		return nmemb
	}
	reader := (*cgoHandle)(userData).Value().(io.Reader)
	buf := make([]byte, 0)
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
	hdr.Data = uintptr(ptr)
	hdr.Len = int(size * nmemb)
	hdr.Cap = hdr.Len
	s := int(size)
	for i := 0; i < int(nmemb); i++ {
		if sz, err := io.ReadFull(reader, buf[i*s:(i+1)*s]); sz < int(size) && err != nil {
			return C.size_t(i)
		}
	}
	return nmemb
}

// writeFull does its best to write all of buf to w. See io.ReadFull.
func writeFull(w io.Writer, buf []byte) (n int, err error) {
	var i int
	for n < len(buf) {
		i, err = w.Write(buf[n:])
		n += i
		if err != nil {
			break
		}
	}
	return
}

//export streamWrite
func streamWrite(ptr unsafe.Pointer, size, nmemb C.size_t, userData unsafe.Pointer) C.size_t {
	if size == 0 || nmemb == 0 {
		return nmemb
	}
	writer := (*cgoHandle)(userData).Value().(io.Writer)
	buf := make([]byte, 0)
	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
	hdr.Data = uintptr(ptr)
	hdr.Len = int(size * nmemb)
	hdr.Cap = hdr.Len
	s := int(size)
	for i := 0; i < int(nmemb); i++ {
		if sz, err := writeFull(writer, buf[i*s:(i+1)*s]); sz < int(size) && err != nil {
			return C.size_t(i)
		}
	}
	return nmemb
}
