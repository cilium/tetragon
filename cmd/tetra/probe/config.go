// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package probe

import (
	"strings"

	"github.com/cilium/tetragon/pkg/kernels"

	"github.com/spf13/cobra"
)

func NewConfigCmd() *cobra.Command {
	cmd := cobra.Command{
		Use:   "config",
		Short: "Probe for the availability of Linux kernel configuration options",
		Run: func(cmd *cobra.Command, _ []string) {
			cmd.Println(strings.ReplaceAll(kernels.LogConfigs(), " ", "\n"))
		},
	}

	return &cmd
}
