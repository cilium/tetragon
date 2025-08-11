// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package debug

import (
	"encoding/json"
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/cilium/tetragon/cmd/tetra/common"
	"github.com/cilium/tetragon/pkg/bugtool"
)

func NewMapCmd() *cobra.Command {
	var lines int
	var output string
	var path string

	cmd := cobra.Command{
		Use:     "maps",
		Aliases: []string{"map"},
		Short:   "Retrieve information about BPF maps on the host related to tetragon",
		Long: fmt.Sprintf(`Retrieve information about maps on the host related to tetragon.

- AllMaps: all the BPF maps loaded on the host
- PinnedProgsMaps: all the BPF maps used in programs pinned under %[1]s
- PinnedMaps: all the BPF maps pinned under %[1]s

The first table is the total of memlock bytes for the maps, those values are
accurate mostly from v6.4[^1].

The second table is in number of maps, inter, exter and union are the respective
math operations on the two first set, diff is the number of maps that were
detected as pinned maps but not used in pinned progs, ideally this number should
be 0. Note that the union should be the set of all the tetragon related maps on
the host if all the programs are properly pinned under the bpffs and all the
unused maps are also pinned under the bpffs.

The third table is the details of the maps that are in the diff, which means
maps that are pinned but unreferenced from pinned programs. Ideally, this table
should be empty.

The fourth table aggregate map by name and add the count column indicating how
many maps were aggregated for the given name. It ranks map from the one
consuming the most memory to the one consuming the less. Use the -n flag to
adjust the number of item in the table.

[^1]: https://lore.kernel.org/all/20230305124615.12358-1-laoar.shao@gmail.com/`, bugtool.TetragonBPFFS),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if output != "tab" && output != "json" {
				return fmt.Errorf("invalid output format %q, please use one of tab or json", output)
			}

			out, err := bugtool.RunMapsChecks(path)
			if err != nil {
				return err
			}

			switch output {
			case "tab":
				w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
				fmt.Fprintln(w, "AllMaps\tPinnedProgsMaps\tPinnedMaps")
				fmt.Fprintf(w, "%s\t%s\t%s\n",
					common.HumanizeByteCount(out.TotalMemlockBytes.AllMaps),
					common.HumanizeByteCount(out.TotalMemlockBytes.PinnedProgsMaps),
					common.HumanizeByteCount(out.TotalMemlockBytes.PinnedMaps),
				)
				w.Flush()
				cmd.Println()

				w = tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
				fmt.Fprintln(w, "PinnedProgsMaps\tPinnedMaps\tInter\tExter\tUnion\tDiff")
				fmt.Fprintf(w, "%d\t%d\t%d\t%d\t%d\t%d\n",
					out.MapsStats.PinnedProgsMaps,
					out.MapsStats.PinnedMaps,
					out.MapsStats.Inter,
					out.MapsStats.Exter,
					out.MapsStats.Union,
					out.MapsStats.Diff,
				)
				w.Flush()
				cmd.Println()

				if len(out.DiffMaps) != 0 {
					w = tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
					fmt.Fprintln(w, "ID\tName\tType\tKeySize\tValueSize\tMaxEntries\tMemlock")
					for _, d := range out.DiffMaps {
						fmt.Fprintf(w, "%d\t%s\t%s\t%d\t%d\t%d\t%s\n",
							d.ID,
							d.Name,
							d.Type,
							d.KeySize,
							d.ValueSize,
							d.MaxEntries,
							common.HumanizeByteCount(d.MemlockBytes),
						)
					}
					w.Flush()
				} else {
					cmd.Println("Empty diff table")
				}
				cmd.Println()

				if len(out.AggregatedMaps) != 0 {
					w = tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
					fmt.Fprintln(w, "Name\tType\tKeySize\tValueSize\tMaxEntries\tCount\tTotalMemlock\tPercentOfTotal")
					for i, d := range out.AggregatedMaps {
						if lines != 0 && i+1 > lines {
							break
						}
						fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%d\t%d\t%s\t%0.1f%%\n",
							d.Name,
							d.Type,
							d.KeySize,
							d.ValueSize,
							d.MaxEntries,
							d.Count,
							common.HumanizeByteCount(d.TotalMemlockBytes),
							d.PercentOfTotal,
						)
					}
					w.Flush()
				} else {
					cmd.Println("Empty BPF memory consumption table")
				}
			case "json":
				jsonOut, err := json.Marshal(out)
				if err != nil {
					return fmt.Errorf("failed to marshal output to JSON: %w", err)
				}
				cmd.Println(string(jsonOut))
			default:
				// this should be caught earlier
				return fmt.Errorf("invalid output format %q, please use one of tab or json", output)
			}

			return nil
		},
	}

	flags := cmd.Flags()
	flags.IntVarP(&lines, "lines", "n", 10, "Number of lines for the top BPF map memory consumers.\nUse 0 to print all lines. Only valid with tab output.")
	flags.StringVarP(&output, "output", "o", "tab", "Output format. One of tab or json.")
	flags.StringVar(&path, "path", bugtool.TetragonBPFFS, "Path of the BPF filesystem.")

	return &cmd
}
