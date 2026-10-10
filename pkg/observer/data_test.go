// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package observer

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
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

// badCount reads the DataEventBad counter so tests can assert that
// rejections are counted. Only the fixed code increments it on these
// inputs, which is what makes the subtests fail without the fix.
func badCount() float64 {
	return testutil.ToFloat64(DataEventStats.WithLabelValues(DataEventTypeStrings[DataEventBad]))
}

func TestHandleData_SizeValidation(t *testing.T) {
	tests := []struct {
		name    string
		size    uint32
		payload []byte
		healthy bool
	}{
		{name: "short size rejected and counted", size: 10},
		{name: "zero length rejected and counted", size: 32},
		{name: "oversize rejected and counted", size: 32 + 4096},
		{name: "healthy accepted", size: 32 + 4, payload: []byte{1, 2, 3, 4}, healthy: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.healthy {
				// Well-formed record must keep flowing into the data
				// cache. The global data cache is nil until initialized.
				require.NoError(t, InitDataCache(1024))
				raw := append(encodeDataHeader(t, tt.size), tt.payload...)
				events, err := HandleData(bytes.NewReader(raw))
				require.NoError(t, err)
				require.Empty(t, events)
				return
			}
			// Rejected records must return an error instead of wrapping
			// the size and allocating ~4GiB (or caching an empty entry),
			// and must be counted via DataEventBad — which only the fixed
			// code does for these inputs. Errors before touching the data
			// cache, so no InitDataCache is required.
			before := badCount()
			_, err := HandleData(bytes.NewReader(encodeDataHeader(t, tt.size)))
			require.ErrorContains(t, err, "failed to add data msg")
			assert.InDelta(t, before+1, badCount(), 1e-9)
		})
	}
}
