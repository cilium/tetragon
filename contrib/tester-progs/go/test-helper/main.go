// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package main

import (
	"github.com/cilium/tetragon/pkg/testutils/progs"
)

func main() {
	progs.TestHelperMain()
}
