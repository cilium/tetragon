// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package api

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBPFReaderReadBytes(t *testing.T) {
	r := NewBPFReader([]byte{1, 2, 3, 4, 5})
	require.Equal(t, 5, r.Len())

	b := make([]byte, 2)
	require.NoError(t, r.ReadBytes(b))
	require.Equal(t, []byte{1, 2}, b)
	require.Equal(t, 3, r.Len())

	// short: fails and consumes nothing
	b = make([]byte, 4)
	require.ErrorIs(t, r.ReadBytes(b), io.ErrUnexpectedEOF)
	require.Equal(t, 3, r.Len())

	b = make([]byte, 3)
	require.NoError(t, r.ReadBytes(b))
	require.Equal(t, []byte{3, 4, 5}, b)
	require.Zero(t, r.Len())

	// zero-length reads always succeed, even when empty
	require.NoError(t, r.ReadBytes(nil))
	require.ErrorIs(t, r.ReadBytes(make([]byte, 1)), io.ErrUnexpectedEOF)
}

func TestBPFReaderReadAtMost(t *testing.T) {
	r := NewBPFReader([]byte{1, 2, 3})

	b := make([]byte, 2)
	n, err := r.ReadAtMost(b)
	require.NoError(t, err)
	require.Equal(t, 2, n)
	require.Equal(t, []byte{1, 2}, b)

	// short read is not an error
	b = make([]byte, 4)
	n, err = r.ReadAtMost(b)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	require.Equal(t, byte(3), b[0])

	n, err = r.ReadAtMost(b)
	require.ErrorIs(t, err, io.EOF)
	require.Zero(t, n)
}

func TestBPFReaderSkip(t *testing.T) {
	r := NewBPFReader([]byte{1, 2, 3, 4})

	require.NoError(t, r.Skip(2))
	require.Equal(t, 2, r.Len())

	// short: fails and consumes nothing
	require.ErrorIs(t, r.Skip(3), io.ErrUnexpectedEOF)
	require.Equal(t, 2, r.Len())

	require.Error(t, r.Skip(-1))
	require.NoError(t, r.Skip(0))

	b := make([]byte, 2)
	require.NoError(t, r.ReadBytes(b))
	require.Equal(t, []byte{3, 4}, b)
}

func TestBPFReaderNoAllocs(t *testing.T) {
	data := make([]byte, 64)
	r := NewBPFReader(data)
	var buf [16]byte

	allocs := testing.AllocsPerRun(100, func() {
		r.r.Reset(data)
		_ = r.ReadBytes(buf[:])
		_, _ = r.ReadAtMost(buf[:])
		_ = r.Skip(4)
		_ = r.Len()
	})
	require.Zero(t, allocs)
}
