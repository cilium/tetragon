// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/cilium/tetragon/pkg/api/tracingapi"
	gt "github.com/cilium/tetragon/pkg/generictypes"
	"github.com/stretchr/testify/assert"
)

func TestGetArgInt32Arr(t *testing.T) {
	tests := []struct {
		name          string
		inputCount    uint32
		inputValues   []int32
		expectedVals  []int32
		expectedError bool
	}{
		{
			name:         "Normal 2 values",
			inputCount:   2,
			inputValues:  []int32{10, 20},
			expectedVals: []int32{10, 20},
		},
		{
			name:         "Normal 5 values",
			inputCount:   5,
			inputValues:  []int32{10, 20, 30, 40, 50},
			expectedVals: []int32{10, 20, 30, 40, 50},
		},
		{
			name:         "Single value",
			inputCount:   1,
			inputValues:  []int32{99},
			expectedVals: []int32{99},
		},
		{
			name:         "Empty array",
			inputCount:   0,
			inputValues:  []int32{},
			expectedVals: []int32{},
		},
		{
			name:         "Saved for retprobe",
			inputCount:   0xFFFFFFFC, // -4 as uint32 indicates a return probe
			inputValues:  []int32{},
			expectedVals: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			err := binary.Write(buf, binary.LittleEndian, tt.inputCount)
			assert.NoError(t, err)

			if tt.inputCount != 0xFFFFFFFC {
				err = binary.Write(buf, binary.LittleEndian, tt.inputValues)
				assert.NoError(t, err)
			}

			r := bytes.NewReader(buf.Bytes())
			argPrinter := argPrinter{
				ty:    gt.GenericInt32ArrType,
				index: 0,
				label: "test_arg",
			}

			res := getArg(r, argPrinter)

			if tt.expectedVals == nil && tt.inputCount == 0xFFFFFFFC {
				typedRes, ok := res.(tracingapi.MsgGenericKprobeArgInt32List)
				assert.True(t, ok, "Expected MsgGenericKprobeArgInt32List")
				assert.Empty(t, typedRes.Value)
			} else {
				typedRes, ok := res.(tracingapi.MsgGenericKprobeArgInt32List)
				assert.True(t, ok, "Expected MsgGenericKprobeArgInt32List")
				assert.Equal(t, tt.expectedVals, typedRes.Value)
			}
		})
	}
}
