// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package api

import (
	"bytes"
	"fmt"
	"io"
)

// BPFReader is a reader over raw event data received from BPF.
//
// It deliberately does not implement io.Reader: event decoding is a hot path
// and encoding/binary.Read() is expensive there (reflection, plus a heap
// allocation per call since the destination escapes through the io.Reader
// interface). Not satisfying io.Reader turns any attempt at calling
// binary.Read() on event data into a compile-time error. Use ReadBPFStruct(),
// ReadIntegerLE() or the methods below instead.
type BPFReader struct {
	r bytes.Reader
}

func NewBPFReader(data []byte) *BPFReader {
	br := &BPFReader{}
	br.r.Reset(data)
	return br
}

func (br *BPFReader) Len() int {
	return br.r.Len()
}

func (br *BPFReader) ReadBytes(b []byte) error {
	if len(b) > br.r.Len() {
		return io.ErrUnexpectedEOF
	}
	_, _ = br.r.Read(b)
	return nil
}

func (br *BPFReader) Skip(n int) error {
	if n < 0 {
		return fmt.Errorf("negative skip: %d", n)
	}
	if n > br.r.Len() {
		return io.ErrUnexpectedEOF
	}
	_, err := br.r.Seek(int64(n), io.SeekCurrent)
	return err
}

func (br *BPFReader) ReadAtMost(b []byte) (int, error) {
	return br.r.Read(b)
}
