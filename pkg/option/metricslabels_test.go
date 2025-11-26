// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package option

import (
	"maps"
	"testing"
)

func TestParseMetricsLabelFilter(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected map[string]bool
	}{
		{
			name:     "all labels (default)",
			input:    "namespace,workload,pod,binary,node_name",
			expected: DefaultLabelFilter(),
		},
		{
			name:     "no labels",
			input:    "",
			expected: map[string]bool{"namespace": false, "workload": false, "pod": false, "binary": false, "node_name": false},
		},
		{
			name:     "without pod",
			input:    "namespace,workload,binary",
			expected: map[string]bool{"namespace": true, "workload": true, "pod": false, "binary": true, "node_name": false},
		},
		{
			name:     "spaces + empty",
			input:    "namespace , workload , ,, binary",
			expected: map[string]bool{"namespace": true, "workload": true, "pod": false, "binary": true, "node_name": false},
		},
		{
			name:     "unknown + misspelled",
			input:    "namespace,workload,unknown,ppod,podd,binary",
			expected: map[string]bool{"namespace": true, "workload": true, "pod": false, "binary": true, "node_name": false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := DefaultLabelFilter().WithEnabledLabels(ParseMetricsLabelFilter(tt.input))
			if !maps.Equal(actual, tt.expected) {
				t.Errorf("%q got parsed as %v, want %v", tt.input, actual, tt.expected)
			}
		})
	}
}
