// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !nok8s

package explain

import (
	"bytes"
	"reflect"
	"strings"
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

func TestValidateOutputFormat(t *testing.T) {
	tests := []struct {
		name    string
		format  string
		wantErr string
	}{
		{name: "default", format: ""},
		{name: "json", format: "json"},
		{name: "yaml", format: "yaml"},
		{name: "invalid", format: "bogus", wantErr: `invalid value for "output" flag: bogus`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOutputFormat(tt.format)
			if tt.wantErr == "" && err != nil {
				t.Fatalf("validateOutputFormat(%q) unexpected error: %v", tt.format, err)
			}
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("validateOutputFormat(%q) expected error", tt.format)
				}
				if err.Error() != tt.wantErr {
					t.Fatalf("validateOutputFormat(%q) error = %q, want %q", tt.format, err.Error(), tt.wantErr)
				}
			}
		})
	}
}

func TestCommandOutputValidation(t *testing.T) {
	t.Run("rejects invalid output", func(t *testing.T) {
		resetExplainGlobals()

		cmd := New()
		cmd.SetArgs([]string{"tracingpolicy", "-o", "bogus"})

		err := cmd.Execute()
		if err == nil {
			t.Fatal("expected invalid output format to fail")
		}
		if got, want := err.Error(), `invalid value for "output" flag: bogus`; got != want {
			t.Fatalf("unexpected error %q, want %q", got, want)
		}
	})

	t.Run("keeps default output", func(t *testing.T) {
		resetExplainGlobals()

		cmd := New()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs([]string{"tracingpolicy"})

		if err := cmd.Execute(); err != nil {
			t.Fatalf("Execute() unexpected error: %v", err)
		}
		if got := out.String(); !strings.Contains(got, "KIND:     TracingPolicy") {
			t.Fatalf("expected default explain output, got %q", got)
		}
	})
}

func resetExplainGlobals() {
	outputFormat = ""
	recursive = false
	showExample = false
	listMode = false
	apiVersion = ""
}
