// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package explain

import (
	"reflect"
	"testing"
)

func TestConvertBracketsToDots(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple bracket",
			input:    "tracingpolicy[spec]",
			expected: "tracingpolicy.spec",
		},
		{
			name:     "nested brackets",
			input:    "tracingpolicy[spec][kprobes]",
			expected: "tracingpolicy.spec.kprobes",
		},
		{
			name:     "mixed notation",
			input:    "tracingpolicy.spec[kprobes]",
			expected: "tracingpolicy.spec.kprobes",
		},
		{
			name:     "empty bracket",
			input:    "tracingpolicy[]",
			expected: "tracingpolicy",
		},
		{
			name:     "numeric index",
			input:    "tracingpolicy.spec.kprobes[0]",
			expected: "tracingpolicy.spec.kprobes",
		},
		{
			name:     "numeric index in middle",
			input:    "tracingpolicy.spec.kprobes[0].call",
			expected: "tracingpolicy.spec.kprobes.call",
		},
		{
			name:     "no brackets",
			input:    "tracingpolicy.spec.kprobes",
			expected: "tracingpolicy.spec.kprobes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := convertBracketsToDots(tt.input)
			if got != tt.expected {
				t.Errorf("convertBracketsToDots(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []string
		wantErr bool
	}{
		{
			name:    "simple path",
			input:   "tracingpolicy.spec",
			want:    []string{"tracingpolicy", "spec"},
			wantErr: false,
		},
		{
			name:    "bracket notation",
			input:   "tracingpolicy[spec][kprobes]",
			want:    []string{"tracingpolicy", "spec", "kprobes"},
			wantErr: false,
		},
		{
			name:    "mixed notation",
			input:   "tracingpolicy.spec[kprobes]",
			want:    []string{"tracingpolicy", "spec", "kprobes"},
			wantErr: false,
		},
		{
			name:    "empty path",
			input:   "",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "starts with dot",
			input:   ".tracingpolicy.spec",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "ends with dot",
			input:   "tracingpolicy.spec.",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "empty segment",
			input:   "tracingpolicy..spec",
			want:    []string{"tracingpolicy", "spec"},
			wantErr: false,
		},
		{
			name:    "whitespace",
			input:   " tracingpolicy . spec ",
			want:    []string{"tracingpolicy", "spec"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizePath(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("normalizePath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("normalizePath() = %v, want %v", got, tt.want)
			}
		})
	}
}
