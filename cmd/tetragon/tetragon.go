// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package main

import (
	"fmt"
	"os"
)

func main() {
	if err := execute(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
