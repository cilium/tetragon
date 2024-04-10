// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package option

import (
	"maps"
	"testing"

	"github.com/cilium/tetragon/pkg/metrics/consts"
)

func TestParseMetricsLabelFilter(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected map[string]bool
	}{
		{
			name:     "all labels (default)",
			input:    "namespace,workload,pod,binary",
			expected: consts.DefaultLabelsFilter,
		},
		{
			name:     "no labels",
			input:    "",
			expected: map[string]bool{"namespace": false, "workload": false, "pod": false, "binary": false},
		},
		{
			name:     "without pod",
			input:    "namespace,workload,binary",
			expected: map[string]bool{"namespace": true, "workload": true, "pod": false, "binary": true},
		},
		{
			name:     "spaces + empty",
			input:    "namespace , workload , ,, binary",
			expected: map[string]bool{"namespace": true, "workload": true, "pod": false, "binary": true},
		},
		{
			name:     "unknown + misspelled",
			input:    "namespace,workload,unknown,ppod,podd,binary",
			expected: map[string]bool{"namespace": true, "workload": true, "pod": false, "binary": true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := parseMetricsLabelFilter(tt.input)
			if !maps.Equal(actual, tt.expected) {
				t.Errorf("parseMetricsLabelFilter(%q) = %v, want %v", tt.input, actual, tt.expected)
			}
		})
	}
}
