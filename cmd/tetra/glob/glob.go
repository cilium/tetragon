// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package glob

import (
	"github.com/cilium/tetragon/pkg/glob"

	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	ret := &cobra.Command{
		Use:   "glob",
		Short: "debug information for glob",
	}

	ret.AddCommand(
		printGlobFSMCmd(),
	)

	return ret
}

func printGlobFSMCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "dump-fsm [pattern]",
		Short: "dump Glob FSM",
		Long: `Print the FSM of a set of Glob patterns for debugging purposes. You can copy
the output into a Graphviz Viewer (i.e. https://graphvizonline.net/) to do
the visualization.

Examples:
  # Print an FSM for a single pattern
  tetra glob dump-fsm "aaa*"

  # Print an FSM for multiple pattern (more than 2 is also supported)
  tetra glob dump-fsm "aaa?" "aab?"`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			allPatterns := map[string][]int32{}
			for i, s := range args {
				allPatterns[s] = []int32{int32(i)}
			}
			literals, _ := glob.GetLiterals(allPatterns)
			nfa := glob.BuildMultiNFA(allPatterns)
			dfa := glob.ToDFA(nfa, literals)
			return glob.ExportToDOT(cmd.OutOrStdout(), dfa)
		},
	}
}
