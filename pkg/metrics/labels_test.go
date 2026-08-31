// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metrics

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/api/ops"
)

// TestOpCodeLabelsAligned checks that the opcode label and its human-readable
// counterpart are index-aligned. Consumers such as
// eventmetrics.collectForDocs pair them by index, so a mismatch would report
// an opcode under the wrong name.
func TestOpCodeLabelsAligned(t *testing.T) {
	for _, tc := range []struct {
		name     string
		opcodes  ConstrainedLabel
		opNames  ConstrainedLabel
		hasUndef bool
	}{
		{"without undef", OpCodeLabel, OpCodeNameLabel, false},
		{"with undef", OpCodeLabelWithUndef, OpCodeNameLabelWithUndef, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, "opcode", tc.opcodes.Name)
			require.Equal(t, "opstr", tc.opNames.Name)
			require.Len(t, tc.opNames.Values, len(tc.opcodes.Values))

			for i, raw := range tc.opcodes.Values {
				code, err := strconv.Atoi(raw)
				require.NoError(t, err, "opcode value %q is not numeric", raw)
				assert.Equal(t, ops.OpCode(code).String(), tc.opNames.Values[i],
					"opcode %d and its name are not aligned at index %d", code, i)
			}

			assert.Contains(t, tc.opcodes.Values, strconv.Itoa(int(ops.MSG_OP_EXECVE)))
			// MSG_OP_TEST is only used for testing and is never exposed.
			assert.NotContains(t, tc.opcodes.Values, strconv.Itoa(int(ops.MSG_OP_TEST)))
			assert.NotContains(t, tc.opNames.Values, ops.OpCode(ops.MSG_OP_TEST).String())

			undef := strconv.Itoa(int(ops.MSG_OP_UNDEF))
			if tc.hasUndef {
				assert.Contains(t, tc.opcodes.Values, undef)
			} else {
				assert.NotContains(t, tc.opcodes.Values, undef)
			}
		})
	}
}

// TestOpCodeLabelsDeterministic checks that label values are stable across
// calls. They're built by ranging over a map, so they must be sorted to keep
// generated documentation from churning.
func TestOpCodeLabelsDeterministic(t *testing.T) {
	for range 10 {
		assert.Equal(t, OpCodeLabel.Values, getOpcodes(false))
		assert.Equal(t, OpCodeNameLabel.Values, getOpcodeNames(false))
		assert.Equal(t, OpCodeLabelWithUndef.Values, getOpcodes(true))
		assert.Equal(t, OpCodeNameLabelWithUndef.Values, getOpcodeNames(true))
	}
}
