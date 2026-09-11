// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package api

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadIntegerLEUint(t *testing.T) {
	r := bytes.NewReader([]byte{
		0x01,
		0x02, 0x00,
		0x03, 0x00, 0x00, 0x00,
		0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	})

	u8, err := ReadIntegerLE[uint8](r)
	require.NoError(t, err)
	require.Equal(t, uint8(1), u8)

	u16, err := ReadIntegerLE[uint16](r)
	require.NoError(t, err)
	require.Equal(t, uint16(2), u16)

	u32, err := ReadIntegerLE[uint32](r)
	require.NoError(t, err)
	require.Equal(t, uint32(3), u32)

	u64, err := ReadIntegerLE[uint64](r)
	require.NoError(t, err)
	require.Equal(t, uint64(4), u64)

	require.Zero(t, r.Len())
}

func TestReadIntegerLEInt(t *testing.T) {
	r := bytes.NewReader([]byte{
		0xff,
		0xfe, 0xff,
		0xfd, 0xff, 0xff, 0xff,
		0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	})

	i8, err := ReadIntegerLE[int8](r)
	require.NoError(t, err)
	require.Equal(t, int8(-1), i8)

	i16, err := ReadIntegerLE[int16](r)
	require.NoError(t, err)
	require.Equal(t, int16(-2), i16)

	i32, err := ReadIntegerLE[int32](r)
	require.NoError(t, err)
	require.Equal(t, int32(-3), i32)

	i64, err := ReadIntegerLE[int64](r)
	require.NoError(t, err)
	require.Equal(t, int64(-4), i64)
}

func TestReadIntegerLEShortRead(t *testing.T) {
	r := bytes.NewReader([]byte{0x01, 0x02, 0x03})

	_, err := ReadIntegerLE[uint32](r)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

func TestReadIntegerLEEmpty(t *testing.T) {
	r := bytes.NewReader(nil)

	_, err := ReadIntegerLE[uint64](r)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

func TestReadIntegerLESequential(t *testing.T) {
	r := bytes.NewReader([]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88})

	a, err := ReadIntegerLE[uint32](r)
	require.NoError(t, err)
	require.Equal(t, uint32(0x44332211), a)

	b, err := ReadIntegerLE[uint32](r)
	require.NoError(t, err)
	require.Equal(t, uint32(0x88776655), b)

	require.Zero(t, r.Len())
}

type testBPFStruct struct {
	A uint32
	B uint16
	C uint16
	D uint64
}

func TestReadBPFStruct(t *testing.T) {
	r := bytes.NewReader([]byte{
		0x01, 0x00, 0x00, 0x00,
		0x02, 0x00,
		0x03, 0x00,
		0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	})

	var dst testBPFStruct
	err := ReadBPFStruct(r, &dst)
	require.NoError(t, err)
	require.Equal(t, testBPFStruct{A: 1, B: 2, C: 3, D: 4}, dst)
	require.Zero(t, r.Len())
}

func TestReadBPFStructShortRead(t *testing.T) {
	r := bytes.NewReader([]byte{0x01, 0x00, 0x00, 0x00, 0x02, 0x00})

	var dst testBPFStruct
	err := ReadBPFStruct(r, &dst)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

func TestReadBPFStructPreservesTrailingData(t *testing.T) {
	r := bytes.NewReader([]byte{
		0x01, 0x00, 0x00, 0x00,
		0x02, 0x00,
		0x03, 0x00,
		0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xaa, 0xbb,
	})

	var dst testBPFStruct
	err := ReadBPFStruct(r, &dst)
	require.NoError(t, err)
	require.Equal(t, testBPFStruct{A: 1, B: 2, C: 3, D: 4}, dst)
	require.Equal(t, 2, r.Len())

	rest, err := ReadIntegerLE[uint16](r)
	require.NoError(t, err)
	require.Equal(t, uint16(0xbbaa), rest)
}
