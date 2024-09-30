// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package debug

import (
	"encoding/json"
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

type DiffMap struct {
	ID         int    `json:"id,omitempty"`
	Name       string `json:"name,omitempty"`
	Type       string `json:"type,omitempty"`
	KeySize    int    `json:"key_size,omitempty"`
	ValueSize  int    `json:"value_size,omitempty"`
	MaxEntries int    `json:"max_entries,omitempty"`
	Memlock    int    `json:"memlock,omitempty"`
}

type AggregatedMap struct {
	Name           string  `json:"name,omitempty"`
	Type           string  `json:"type,omitempty"`
	KeySize        int     `json:"key_size,omitempty"`
	ValueSize      int     `json:"value_size,omitempty"`
	MaxEntries     int     `json:"max_entries,omitempty"`
	Count          int     `json:"count,omitempty"`
	TotalMemlock   int     `json:"total_memlock,omitempty"`
	PercentOfTotal float64 `json:"percent_of_total,omitempty"`
}

type mapCommandOutput struct {
	TotalByteMemlock struct {
		AllMaps         int `json:"all_maps,omitempty"`
		PinnedProgsMaps int `json:"pinned_progs_maps,omitempty"`
		PinnedMaps      int `json:"pinned_maps,omitempty"`
	} `json:"total_byte_memlock,omitempty"`

	MapsStats struct {
		PinnedProgsMaps int `json:"pinned_progs_maps,omitempty"`
		PinnedMaps      int `json:"pinned_maps,omitempty"`
		Inter           int `json:"inter,omitempty"`
		Exter           int `json:"exter,omitempty"`
		Union           int `json:"union,omitempty"`
		Diff            int `json:"diff,omitempty"`
	} `json:"maps_stats,omitempty"`

	DiffMaps []DiffMap `json:"diff_maps,omitempty"`

	AggregatedMaps []AggregatedMap `json:"aggregated_maps,omitempty"`
}

func (out mapCommandOutput) printJSON(cmd cobra.Command) error {
	jsonOut, err := json.Marshal(out)
	if err != nil {
		return fmt.Errorf("failed to marshal output to JSON: %w", err)
	}
	cmd.Println(string(jsonOut))
	return nil
}

func (out mapCommandOutput) printTables(cmd cobra.Command, lines int) {
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "AllMaps\tPinnedProgsMaps\tPinnedMaps")
	fmt.Fprintf(w, "%d\t%d\t%d\n",
		out.TotalByteMemlock.AllMaps,
		out.TotalByteMemlock.PinnedProgsMaps,
		out.TotalByteMemlock.PinnedMaps,
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
			fmt.Fprintf(w, "%d\t%s\t%s\t%d\t%d\t%d\t%d\n",
				d.ID,
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

	if len(out.AggregatedMaps) != 0 {
		w = tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "Name\tType\tKeySize\tValueSize\tMaxEntries\tCount\tTotalMemlock\tPercentOfTotal")
		for i, d := range out.AggregatedMaps {
			if lines != 0 && i+1 > lines {
				break
			}
			fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%d\t%d\t%d\t%0.1f%%\n",
				d.Name,
				d.Type,
				d.KeySize,
				d.ValueSize,
				d.MaxEntries,
				d.Count,
				d.TotalMemlock,
				d.PercentOfTotal,
			)
		}
		w.Flush()
	} else {
		cmd.Println("Empty BPF memory consumption table")
	}
}

func NewMapCmd() *cobra.Command {
	var lines int
	var output string

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
			if output != "tab" && output != "json" {
				return fmt.Errorf("invalid output format %q, please use one of tab or json", output)
			}

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

			var out mapCommandOutput

			// BPF maps memory usage
			out.TotalByteMemlock.AllMaps = bugtool.TotalByteMemlock(allMaps)
			out.TotalByteMemlock.PinnedProgsMaps = bugtool.TotalByteMemlock(pinnedProgsMaps)
			out.TotalByteMemlock.PinnedMaps = bugtool.TotalByteMemlock(pinnedMaps)

			// details on map distribution
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

			diff := diff(pinnedMapsSet, pinnedProgsMapsSet)
			union := union(pinnedMapsSet, pinnedProgsMapsSet)

			out.MapsStats.PinnedProgsMaps = len(pinnedProgsMapsSet)
			out.MapsStats.PinnedMaps = len(pinnedMaps)
			out.MapsStats.Inter = len(inter(pinnedMapsSet, pinnedProgsMapsSet))
			out.MapsStats.Exter = len(exter(pinnedMapsSet, pinnedProgsMapsSet))
			out.MapsStats.Union = len(union)
			out.MapsStats.Diff = len(diff)

			// details on diff maps
			for _, d := range diff {
				id, ok := d.ID()
				if !ok {
					return errors.New("failed retrieving map ID, need >= 4.13, kernel is too old")
				}
				out.DiffMaps = append(out.DiffMaps, DiffMap{
					ID:         int(id),
					Name:       d.Name,
					Type:       d.Type.String(),
					KeySize:    int(d.KeySize),
					ValueSize:  int(d.ValueSize),
					MaxEntries: int(d.MaxEntries),
					Memlock:    d.Memlock,
				})
			}

			// aggregates maps total memory use
			aggregatedMapsSet := map[string]struct {
				bugtool.ExtendedMapInfo
				count int
			}{}
			var total int
			for _, m := range union {
				total += m.Memlock
				if e, exist := aggregatedMapsSet[m.Name]; exist {
					e.Memlock += m.Memlock
					e.count++
					aggregatedMapsSet[m.Name] = e
				} else {
					aggregatedMapsSet[m.Name] = struct {
						bugtool.ExtendedMapInfo
						count int
					}{m, 1}
				}
			}
			aggregatedMaps := maps.Values(aggregatedMapsSet)
			sort.Slice(aggregatedMaps, func(i, j int) bool {
				return aggregatedMaps[i].Memlock > aggregatedMaps[j].Memlock
			})

			for _, m := range aggregatedMaps {
				out.AggregatedMaps = append(out.AggregatedMaps, AggregatedMap{
					Name:           m.Name,
					Type:           m.Type.String(),
					KeySize:        int(m.KeySize),
					ValueSize:      int(m.ValueSize),
					MaxEntries:     int(m.MaxEntries),
					Count:          m.count,
					TotalMemlock:   m.Memlock,
					PercentOfTotal: float64(m.Memlock) / float64(total) * 100,
				})
			}

			switch output {
			case "tab":
				out.printTables(*cmd, lines)
			case "json":
				err := out.printJSON(*cmd)
				if err != nil {
					return err
				}
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
