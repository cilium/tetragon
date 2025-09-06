// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package bugtool

import (
	"github.com/spf13/cobra"

	"github.com/cilium/tetragon/pkg/bugtool"
)

var (
	outFile string
	bpfTool string
	gops    string
)

type Command struct {
	command        *cobra.Command
	CommandActions []bugtool.CommandAction
	GRPCActions    []bugtool.GRPCAction
}

func (c *Command) WithCommandAction(action bugtool.CommandAction) *Command {
	c.CommandActions = append(c.CommandActions, action)
	return c
}
func (c *Command) WithGRPCAction(action bugtool.GRPCAction) *Command {
	c.GRPCActions = append(c.GRPCActions, action)
	return c
}

func (c *Command) Command() *cobra.Command {
	return c.command
}

func New() *Command {
	bugtoolCmd := &Command{
		CommandActions: make([]bugtool.CommandAction, 0),
		GRPCActions:    make([]bugtool.GRPCAction, 0),
	}
	bugtoolCmd.command = &cobra.Command{
		Use:   "bugtool",
		Short: "Produce a tar archive with debug information",
		Run: func(_ *cobra.Command, _ []string) {
			bugtool.Bugtool(outFile, bpfTool, gops, bugtoolCmd.CommandActions, bugtoolCmd.GRPCActions)
		},
	}

	flags := bugtoolCmd.command.Flags()
	flags.StringVarP(&outFile, "out", "o", "tetragon-bugtool.tar.gz", "Output filename")
	flags.StringVar(&bpfTool, "bpftool", "", "Path to bpftool binary")
	flags.StringVar(&gops, "gops", "", "Path to gops binary")
	return bugtoolCmd
}
