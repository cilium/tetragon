// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package api

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"unsafe"
)

type Integer interface {
	~int8 | ~int16 | ~int32 | ~int64 | ~uint8 | ~uint16 | ~uint32 | ~uint64
}

// ReadIntegerLE is a zero heap allocation convenience function, an
// alternative to the more expensive binary.Read(). binary.Read() takes its
// reader as an io.Reader interface, so it must heap-allocate the temporary
// buffer it reads into on every call, since escape analysis can't see past
// the interface's dynamic dispatch to prove the buffer doesn't escape.
func ReadIntegerLE[T Integer](r *bytes.Reader) (T, error) {
	var v T
	size := int(unsafe.Sizeof(v))

	if size > r.Len() {
		return 0, io.ErrUnexpectedEOF
	}

	var buf [8]byte
	n, err := r.Read(buf[:size])
	if err != nil {
		return 0, err
	}

	if n != size {
		return 0, io.ErrUnexpectedEOF
	}

	switch size {
	case 1:
		return T(buf[0]), nil
	case 2:
		return T(binary.LittleEndian.Uint16(buf[:2])), nil
	case 4:
		return T(binary.LittleEndian.Uint32(buf[:4])), nil
	case 8:
		return T(binary.LittleEndian.Uint64(buf[:8])), nil
	}

	return 0, fmt.Errorf("unsupported integer size %d", size)
}

func ReadBPFStruct[T any](r *bytes.Reader, dst *T) error {
	buf := unsafe.Slice((*byte)(unsafe.Pointer(dst)), unsafe.Sizeof(*dst))
	if len(buf) > r.Len() {
		return io.ErrUnexpectedEOF
	}

	n, err := r.Read(buf)
	if err != nil {
		return err
	}

	if n != len(buf) {
		return io.ErrUnexpectedEOF
	}

	return nil
}
