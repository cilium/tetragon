// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package main

import (
	"os"

	"github.com/spf13/cobra"
)

func main() {
	cmd := &cobra.Command{
		Use:   "tetragon-vmtests-run",
		Short: "run tetragon tests in little-vm-helper VMs",
	}

	cmd.AddCommand(goTestCmd())
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
