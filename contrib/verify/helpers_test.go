// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package verify

import (
	"slices"
	"testing"
)

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

func TestExtractBaseName(t *testing.T) {
	tests := []struct {
		fileName string
		expected string
	}{
		{"bpf_generic_kprobe_v612.o", "bpf_generic_kprobe"},
		{"bpf_generic_kprobe_v61.o", "bpf_generic_kprobe"},
		{"bpf_generic_kprobe_v511.o", "bpf_generic_kprobe"},
		{"bpf_generic_kprobe.o", "bpf_generic_kprobe"},
		{"bpf_alignchecker.o", "bpf_alignchecker"},
		{"bpf_loader_v511.o", "bpf_loader"},
		{"bpf_loader.o", "bpf_loader"},
	}

	for _, tt := range tests {
		t.Run(tt.fileName, func(t *testing.T) {
			result := extractBaseName(tt.fileName)
			if result != tt.expected {
				t.Errorf("extractBaseName(%q) = %q, want %q", tt.fileName, result, tt.expected)
			}
		})
	}
}

func TestSelectKernelVersionFiles(t *testing.T) {
	tests := []struct {
		name          string
		kernelVersion string
		fileNames     []string
		expectedFiles []string
	}{
		{
			name:          "single file no version",
			kernelVersion: "6.1.0",
			fileNames: []string{
				"bpf_alignchecker.o",
			},
			expectedFiles: []string{
				"bpf_alignchecker.o",
			},
		},
		{
			name:          "selects highest compatible version",
			kernelVersion: "6.7.0",
			fileNames: []string{
				"bpf_generic_kprobe.o",
				"bpf_generic_kprobe_v511.o",
				"bpf_generic_kprobe_v61.o",
				"bpf_generic_kprobe_v612.o",
			},
			expectedFiles: []string{
				"bpf_generic_kprobe_v61.o",
			},
		},
		{
			name:          "falls back to base when all versions too new",
			kernelVersion: "5.4.0",
			fileNames: []string{
				"bpf_test.o",
				"bpf_test_v612.o",
			},
			expectedFiles: []string{
				"bpf_test.o",
			},
		},
		{
			name:          "different programs selected independently",
			kernelVersion: "5.15.0",
			fileNames: []string{
				"bpf_loader.o",
				"bpf_loader_v511.o",
				"bpf_fork.o",
				"bpf_fork_v511.o",
			},
			expectedFiles: []string{
				"bpf_loader_v511.o",
				"bpf_fork_v511.o",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := selectKernelVersionFiles(tt.fileNames, tt.kernelVersion)
			if err != nil {
				t.Fatalf("selectKernelVersionFiles failed: %v", err)
			}

			selected := make(map[string]bool)
			for _, selection := range result {
				selected[selection.SelectedFile] = true
			}

			if len(selected) != len(tt.expectedFiles) {
				t.Errorf("Expected %d files, got %d", len(tt.expectedFiles), len(selected))
			}

			for _, expectedFile := range tt.expectedFiles {
				if !selected[expectedFile] {
					t.Errorf("Expected file %q to be selected, but it wasn't", expectedFile)
				}
			}

			for selectedFile := range selected {
				found := slices.Contains(tt.expectedFiles, selectedFile)
				if !found {
					t.Errorf("File %q was selected but not expected", selectedFile)
				}
			}
		})
	}
}
