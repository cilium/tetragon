// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package observer

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/api/dataapi"
	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/api/processapi"
)

// encodeDataHeader builds a MSG_OP_DATA record header with the given
// declared size and no implicit payload.
func encodeDataHeader(t *testing.T, size uint32) []byte {
	t.Helper()
	var buf bytes.Buffer
	hdr := dataapi.MsgData{
		Common: processapi.MsgCommon{Op: uint8(ops.MSG_OP_DATA), Size: size},
		Id:     dataapi.DataEventId{Pid: 1234, Time: 5678},
	}
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, &hdr))
	return buf.Bytes()
}

func TestHandleData_ShortSizeReturnsError(t *testing.T) {
	// Full 32-byte header with Size smaller than the header itself.
	// Must return an error instead of wrapping the size and
	// allocating ~4GiB. Errors before touching the data cache,
	// so no InitDataCache is required.
	_, err := HandleData(bytes.NewReader(encodeDataHeader(t, 10)))
	require.ErrorContains(t, err, "failed to add data msg")
}

func TestHandleData_PayloadExceedsReaderReturnsError(t *testing.T) {
	// Declared payload (4096) larger than the bytes actually present (0).
	_, err := HandleData(bytes.NewReader(encodeDataHeader(t, 32+4096)))
	require.ErrorContains(t, err, "failed to add data msg")
}

func TestHandleData_HealthyStillWorks(t *testing.T) {
	// Well-formed record must keep flowing into the data cache.
	// The global data cache is nil until initialized.
	require.NoError(t, InitDataCache(1024))
	payload := []byte{1, 2, 3, 4}
	raw := append(encodeDataHeader(t, 32+uint32(len(payload))), payload...)
	events, err := HandleData(bytes.NewReader(raw))
	require.NoError(t, err)
	require.Empty(t, events)
}
