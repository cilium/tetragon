// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package bugtool

import (
	"github.com/cilium/tetragon/pkg/bugtool"

	"github.com/spf13/cobra"
)

var (
	outFile string
	bpfTool string
)

func New() *cobra.Command {
	bugtoolCmd := &cobra.Command{
		Use:   "bugtool",
		Short: "Produce a tar archive with debug information",
		Run: func(cmd *cobra.Command, args []string) {
			bugtool.Bugtool(outFile, bpfTool)
		},
	}

	flags := bugtoolCmd.Flags()
	flags.StringVarP(&outFile, "out", "o", "tetragon-bugtool.tar.gz", "Output filename")
	flags.StringVar(&bpfTool, "bpftool", "", "Path to bpftool binary")
	return bugtoolCmd
}
