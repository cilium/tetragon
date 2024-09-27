// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package debug

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/cilium/tetragon/pkg/bugtool"
	"github.com/spf13/cobra"
	"golang.org/x/exp/maps"
)

const tetragonBPFFS = "/sys/fs/bpf/tetragon"

func NewMapCmd() *cobra.Command {
	var lines int

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

[^1]: https://lore.kernel.org/all/20230305124615.12358-1-laoar.shao@gmail.com/`, tetragonBPFFS),
		RunE: func(cmd *cobra.Command, _ []string) error {
			// check that the bpffs exists and we have permissions
			_, err := os.Stat(tetragonBPFFS)
			if err != nil {
				return fmt.Errorf("make sure tetragon is running and you have enough permissions: %w", err)
			}

			// retrieve map infos
			allMaps, err := bugtool.FindAllMaps()
			if err != nil {
				return fmt.Errorf("failed to retrieve all maps: %w", err)
			}
			pinnedProgsMaps, err := bugtool.FindMapsUsedByPinnedProgs(tetragonBPFFS)
			if err != nil {
				return fmt.Errorf("failed to retrieve maps used by pinned progs: %w", err)
			}
			pinnedMaps, err := bugtool.FindPinnedMaps(tetragonBPFFS)
			if err != nil {
				return fmt.Errorf("failed to retrieve pinned maps: %w", err)
			}

			// print BPF maps memory usage
			allMapsMem := bugtool.TotalByteMemlock(allMaps)
			pinnedProgsMapsMem := bugtool.TotalByteMemlock(pinnedProgsMaps)
			pinnedMapsMem := bugtool.TotalByteMemlock(pinnedMaps)
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "AllMaps\tPinnedProgsMaps\tPinnedMaps")
			fmt.Fprintf(w, "%d\t%d\t%d\n", allMapsMem, pinnedProgsMapsMem, pinnedMapsMem)
			w.Flush()
			cmd.Println()

			// print details on map distribution
			pinnedProgsMapsSet := map[int]bugtool.ExtendedMapInfo{}
			for _, info := range pinnedProgsMaps {
				id, ok := info.ID()
				if !ok {
					return errors.New("failed retrieving progs ID, need >= 4.13, kernel is too old")
				}
				pinnedProgsMapsSet[int(id)] = info
			}

			pinnedMapsSet := map[int]bugtool.ExtendedMapInfo{}
			for _, info := range pinnedMaps {
				id, ok := info.ID()
				if !ok {
					return errors.New("failed retrieving map ID, need >= 4.13, kernel is too old")
				}
				pinnedMapsSet[int(id)] = info
			}

			w = tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "PinnedProgsMaps\tPinnedMaps\tInter\tExter\tUnion\tDiff")
			diff := diff(pinnedMapsSet, pinnedProgsMapsSet)
			union := union(pinnedMapsSet, pinnedProgsMapsSet)
			fmt.Fprintf(w, "%d\t%d\t%d\t%d\t%d\t%d\n",
				len(pinnedProgsMapsSet),
				len(pinnedMapsSet),
				len(inter(pinnedMapsSet, pinnedProgsMapsSet)),
				len(exter(pinnedMapsSet, pinnedProgsMapsSet)),
				len(union),
				len(diff),
			)
			w.Flush()
			cmd.Println()

			// print details on the diff
			if len(diff) != 0 {
				w = tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
				fmt.Fprintln(w, "ID\tName\tType\tKeySize\tValueSize\tMaxEntries\tMemlock")
				for _, d := range diff {
					id, ok := d.ID()
					if !ok {
						return errors.New("failed retrieving map ID, need >= 4.13, kernel is too old")
					}
					fmt.Fprintf(w, "%d\t%s\t%s\t%d\t%d\t%d\t%d\n",
						id,
						d.Name,
						d.Type,
						d.KeySize,
						d.ValueSize,
						d.MaxEntries,
						d.Memlock,
					)
				}
				w.Flush()
			} else {
				cmd.Println("Empty diff table")
			}
			cmd.Println()

			if len(union) != 0 {
				w = tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
				fmt.Fprintln(w, "Name\tType\tKeySize\tValueSize\tMaxEntries\tCount\tTotalMemlock\tPercentOfTotal")
				aggregatedMapsSet := map[string]struct {
					bugtool.ExtendedMapInfo
					number int
				}{}
				var total int
				for _, m := range union {
					total += m.Memlock
					if e, exist := aggregatedMapsSet[m.Name]; exist {
						e.Memlock += m.Memlock
						e.number++
						aggregatedMapsSet[m.Name] = e
					} else {
						aggregatedMapsSet[m.Name] = struct {
							bugtool.ExtendedMapInfo
							number int
						}{m, 1}
					}
				}
				aggregatedMaps := maps.Values(aggregatedMapsSet)
				sort.Slice(aggregatedMaps, func(i, j int) bool {
					return aggregatedMaps[i].Memlock > aggregatedMaps[j].Memlock
				})
				for i, d := range aggregatedMaps {
					if lines != 0 && i+1 > lines {
						break
					}
					fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%d\t%d\t%d\t%0.1f%%\n",
						d.Name,
						d.Type,
						d.KeySize,
						d.ValueSize,
						d.MaxEntries,
						d.number,
						d.Memlock,
						float64(d.Memlock)/float64(total)*100,
					)
				}
				w.Flush()
			} else {
				cmd.Println("Empty BPF memory consumption table")
			}
			return nil
		},
	}

	flags := cmd.Flags()
	flags.IntVarP(&lines, "lines", "n", 10, "Number of lines for the top BPF map memory consumers. Use 0 to print all lines.")

	return &cmd
}

func inter[T any](m1, m2 map[int]T) map[int]T {
	ret := map[int]T{}
	for i := range m1 {
		if _, exists := m2[i]; exists {
			ret[i] = m1[i]
		}
	}
	return ret
}

func diff[T any](m1, m2 map[int]T) map[int]T {
	ret := map[int]T{}
	for i := range m1 {
		if _, exists := m2[i]; !exists {
			ret[i] = m1[i]
		}
	}
	return ret
}

func exter[T any](m1, m2 map[int]T) map[int]T {
	ret := map[int]T{}
	for i := range m1 {
		if _, exists := m2[i]; !exists {
			ret[i] = m1[i]
		}
	}
	for i := range m2 {
		if _, exists := m1[i]; !exists {
			ret[i] = m2[i]
		}
	}
	return ret
}

func union[T any](m1, m2 map[int]T) map[int]T {
	ret := map[int]T{}
	for i := range m1 {
		ret[i] = m1[i]
	}
	for i := range m2 {
		ret[i] = m2[i]
	}
	return ret
}
