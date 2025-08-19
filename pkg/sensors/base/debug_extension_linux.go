// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package base

import "github.com/cilium/tetragon/pkg/sensors/program"

// getPlatformDebugProgram returns the Linux-specific program to associate debug maps with
func getPlatformDebugProgram() *program.Program {
	// On Linux, associate debug maps with the Execve program since it includes debug.h
	return Execve
}
