// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

// #cgo LDFLAGS: -Wl,--export-dynamic
// __attribute__((aligned(64))) int add(int a, int b) { return a + b; }
// __attribute__((aligned(64))) int sub(int a, int b) { return a - b; }
import "C"

//go:noinline
func double(x int) int { return 2 * x }

func main() {
	_ = double(1)
	_ = C.sub(3, 1)
}
