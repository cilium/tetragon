// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package api

import (
	"bytes"
	"io"
	"unsafe"
)

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
