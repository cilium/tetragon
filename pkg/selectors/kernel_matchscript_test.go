// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package selectors

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/api/processapi"
)

// TestGeneratePathVariants validates generatePathVariants creates correct bidirectional path variants
// for matchScript functionality, enabling single policy entries to match both absolute and relative paths.
func TestGeneratePathVariants(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "empty path",
			input:    "",
			expected: []string{},
		},
		{
			name:     "absolute path",
			input:    "/tmp/test_script.sh",
			expected: []string{"/tmp/test_script.sh", "./test_script.sh", "test_script.sh"},
		},
		{
			name:     "relative path",
			input:    "./script.sh",
			expected: []string{"./script.sh", "script.sh"},
		},
		{
			name:     "basename only",
			input:    "script.sh",
			expected: []string{"script.sh", "./script.sh"},
		},
		{
			name:     "root path",
			input:    "/script.sh",
			expected: []string{"/script.sh", "./script.sh", "script.sh"},
		},
		{
			name:     "nested absolute path",
			input:    "/usr/local/bin/myscript",
			expected: []string{"/usr/local/bin/myscript", "./myscript", "myscript"},
		},
		{
			name:     "path with special characters",
			input:    "/tmp/script-test_v1.sh",
			expected: []string{"/tmp/script-test_v1.sh", "./script-test_v1.sh", "script-test_v1.sh"},
		},
		{
			name:     "very long path exceeds limit",
			input:    "/very/long/path/" + strings.Repeat("a", processapi.BINARY_PATH_MAX_LEN),
			expected: []string{"/very/long/path/" + strings.Repeat("a", processapi.BINARY_PATH_MAX_LEN), "./" + strings.Repeat("a", processapi.BINARY_PATH_MAX_LEN), strings.Repeat("a", processapi.BINARY_PATH_MAX_LEN)},
		},
	}

	// Run each test case
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Call generatePathVariants function with input path
			result := generatePathVariants(tt.input)
			// Assert result matches expected output
			require.Equal(t, tt.expected, result, "generatePathVariants(%q) should return expected variants", tt.input)
		})
	}
}

// setupKernelSelectorState creates a fresh KernelSelectorState for testing.
func setupKernelSelectorState() *KernelSelectorState {
	return &KernelSelectorState{
		matchBinariesPaths: make(map[int][][processapi.BINARY_PATH_MAX_LEN]byte),
	}
}

// extractPathsFromMap extracts string paths from KernelSelectorState map entries.
func extractPathsFromMap(paths [][processapi.BINARY_PATH_MAX_LEN]byte) []string {
	// Initialize empty slice to avoid nil vs empty slice comparison issues
	result := make([]string, 0)
	for _, bytePath := range paths {
		pathStr := string(bytePath[:])
		if nullIndex := strings.Index(pathStr, "\x00"); nullIndex != -1 {
			pathStr = pathStr[:nullIndex]
		}
		result = append(result, pathStr)
	}
	return result
}

// TestWriteMatchScriptPaths validates writeMatchScriptPaths correctly writes path variants
// to BPF maps based on matchScript flag, ensuring proper integration with kernel selectors.
func TestWriteMatchScriptPaths(t *testing.T) {
	tests := []struct {
		name          string
		path          string
		isMatchScript bool
		expectedPaths []string
	}{
		{
			name:          "non-matchScript path",
			path:          "/tmp/test.sh",
			isMatchScript: false,
			expectedPaths: []string{"/tmp/test.sh"},
		},
		{
			name:          "matchScript absolute path",
			path:          "/tmp/test.sh",
			isMatchScript: true,
			expectedPaths: []string{"/tmp/test.sh", "./test.sh", "test.sh"},
		},
		{
			name:          "matchScript relative path",
			path:          "./test.sh",
			isMatchScript: true,
			expectedPaths: []string{"./test.sh", "test.sh"},
		},
		{
			name:          "matchScript with empty path",
			path:          "",
			isMatchScript: true,
			expectedPaths: []string{},
		},
		{
			name:          "path too long gets truncated",
			path:          "/" + strings.Repeat("x", processapi.BINARY_PATH_MAX_LEN+10),
			isMatchScript: true,
			expectedPaths: []string{}, // Should be filtered out due to length
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := setupKernelSelectorState()
			
			err := writeMatchScriptPaths(k, 1, tt.path, tt.isMatchScript)
			require.NoError(t, err, "writeMatchScriptPaths should not return error for valid input")
			
			// Extract and validate written paths
			writtenPaths := k.matchBinariesPaths[1]
			actualPaths := extractPathsFromMap(writtenPaths)
			
			require.Equal(t, tt.expectedPaths, actualPaths, "writeMatchScriptPaths should write expected paths to map")
		})
	}
}

// BenchmarkGeneratePathVariants measures performance of path variant generation.
func BenchmarkGeneratePathVariants(b *testing.B) {
	testPaths := []string{
		"/usr/bin/python3",
		"./script.py", 
		"script.sh",
		"/very/long/nested/path/to/executable",
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, path := range testPaths {
			_ = generatePathVariants(path)
		}
	}
}
