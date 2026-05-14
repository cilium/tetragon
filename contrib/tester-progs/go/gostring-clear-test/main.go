// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"os"

	"github.com/cilium/tetragon/pkg/sensors/tracing/goabitest"
)

func main() {
	if len(os.Args) < 2 {
		os.Exit(99)
	}
	goabitest.ReportLenForABI(os.Args[1])
}
