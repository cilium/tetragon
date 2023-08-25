// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"fmt"
	"os"

	checker "github.com/cilium/tetragon/pkg/alignchecker"
)

func main() {
	bpfObjPath := "bpf/objs/bpf_alignchecker.o"

	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <path>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "using: %s as object file\n", bpfObjPath)
	} else {
		bpfObjPath = os.Args[1]
	}

	if _, err := os.Stat(bpfObjPath); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot check alignment against %s: %s\n", bpfObjPath, err)
		os.Exit(1)
	}
	if err := checker.CheckStructAlignments(bpfObjPath); err != nil {
		fmt.Fprintf(os.Stderr, "C and Go structs alignment check failed: %s\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stdout, "OK\n")
}
