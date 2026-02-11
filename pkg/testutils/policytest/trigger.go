// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"context"
	"os/exec"
)

// CmdTrigger simply wraps a exec.CommandContext().Run() into a Trigger
type CmdTrigger struct {
	Bin  string
	Args []string
}

func NewCmdTrigger(bin string, args ...string) *CmdTrigger {
	return &CmdTrigger{
		Bin:  bin,
		Args: args,
	}
}

func (c *CmdTrigger) Trigger(ctx context.Context) error {
	return exec.CommandContext(ctx, c.Bin, c.Args...).Run()
}
