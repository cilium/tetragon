// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package cgtracker

import (
	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	ret := &cobra.Command{
		Use:          "cgtracker",
		Short:        "manage cgtracker map (only for debugging)",
		Hidden:       true,
		SilenceUsage: true,
	}

	ret.AddCommand(
		dumpCmd(),
		addCommand(),
	)

	return ret
}

func dumpCmd() *cobra.Command {

	return nil
}

func addCommand() *cobra.Command {

	return nil
}
