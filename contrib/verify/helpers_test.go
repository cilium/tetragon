// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package verify

import "testing"

func TestExtractKernelVersion(t *testing.T) {
	tests := []struct {
		fileName string
		expected string
	}{
		{"bpf_generic_kprobe_v612.o", "6.12"},
		{"bpf_generic_kprobe_v61.o", "6.1"},
		{"bpf_generic_kprobe_v511.o", "5.11"},
		{"bpf_generic_kprobe_v53.o", "5.3"},
		{"bpf_generic_kprobe.o", ""},
		{"bpf_alignchecker.o", ""},
		{"bpf_loader_v511.o", "5.11"},
	}

	for _, tt := range tests {
		t.Run(tt.fileName, func(t *testing.T) {
			result := extractKernelVersion(tt.fileName)
			if result != tt.expected {
				t.Errorf("extractKernelVersion(%q) = %q, want %q", tt.fileName, result, tt.expected)
			}
		})
	}
}
