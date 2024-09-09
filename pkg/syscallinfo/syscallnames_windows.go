// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build windows && (arm64 || amd64)

package syscallinfo

import "errors"

// Define syscalNames variable so that we can compile tetra CLI for windows.
var syscallNames = map[int]string{}
var syscallNames32 = map[int]string{}

func syscallID(n string, abi string) (int, error) {
	return -1, errors.New("syscall ID not supported in windows")
}
