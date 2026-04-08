// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		os.Exit(99)
	}
	fmt.Println(strings.ToUpper(os.Args[1]))
}
