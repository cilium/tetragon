// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build windows && (arm64 || amd64)

package syscallinfo

// Define syscalNames variable so that we can compile tetra CLI for windows.
var syscallNames = map[int]string{}
