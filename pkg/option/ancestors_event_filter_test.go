// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package option

import (
	"maps"
	"testing"
)

func TestParseEnableAncestors(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected map[string]bool
	}{
		{
			name:     "no event types (default)",
			input:    "",
			expected: DefaultEnableAncestors(),
		},
		{
			name:     "all event types",
			input:    "base,kprobe,tracepoint,uprobe,lsm",
			expected: map[string]bool{"base": true, "kprobe": true, "tracepoint": true, "uprobe": true, "lsm": true},
		},
		{
			name:     "without base",
			input:    "kprobe,tracepoint,uprobe,lsm",
			expected: map[string]bool{"base": false, "kprobe": false, "tracepoint": false, "uprobe": false, "lsm": false},
		},
		{
			name:     "spaces + empty",
			input:    "base , kprobe , ,, lsm",
			expected: map[string]bool{"base": true, "kprobe": true, "tracepoint": false, "uprobe": false, "lsm": true},
		},
		{
			name:     "unknown + misspelled",
			input:    "base,kprobe,unknown,ttracepoint,uprobee,lssm",
			expected: map[string]bool{"base": true, "kprobe": true, "tracepoint": false, "uprobe": false, "lsm": false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := DefaultEnableAncestors().WithEnabledAncestors(ParseEnableAncestors(tt.input))
			if !maps.Equal(actual, tt.expected) {
				t.Errorf("%q got parsed as %v, want %v", tt.input, actual, tt.expected)
			}
		})
	}
}
