// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package debug

import (
	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	cmd := cobra.Command{
		Use:    "debug",
		Short:  "Tools to debug tetragon",
		Hidden: true,
	}
	cmd.AddCommand(NewMapCmd())
	cmd.AddCommand(NewDumpCommand())
	cmd.AddCommand(NewProgsCmd())
	cmd.AddCommand(NewEnableStatsCmd())
	return &cmd
}
