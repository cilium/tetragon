// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package base

import "github.com/cilium/tetragon/pkg/sensors/program"

// getPlatformDebugProgram returns the Windows-specific program to associate debug maps with
func getPlatformDebugProgram() *program.Program {
	// On Windows, associate debug maps with the CreateProcess program (Windows equivalent of Execve)
	// Windows uses ringbuf maps instead of perf event arrays
	return CreateProcess
}
