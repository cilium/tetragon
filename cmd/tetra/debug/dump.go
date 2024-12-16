// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package debug

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/cmd/tetra/common"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/errmetrics"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/cilium/tetragon/pkg/sensors/exec/execvemap"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
)

// NewDumpAlias return a hidden alias of the dump subcommand, dump used to be a
// top level commands and was moved under debug, this avoids a breaking change.
func NewDumpAlias() *cobra.Command {
	legacyDump := NewDumpCommand()
	legacyDump.Hidden = true
	return legacyDump
}

func NewDumpCommand() *cobra.Command {
	ret := &cobra.Command{
		Use:          "dump",
		Short:        "Dump information from tetragon maps and caches",
		SilenceUsage: true,
	}

	ret.AddCommand(
		execveMapCmd(),
		policyfilterCmd(),
		dumpProcessCache(),
		bpfErrMetricsCmd(),
	)

	return ret
}

func execveMapCmd() *cobra.Command {
	mapFname := filepath.Join(defaults.DefaultMapRoot, defaults.DefaultMapPrefix, base.ExecveMap.Name)
	ret := &cobra.Command{
		Use:   "execve",
		Short: "dump execve map",
		Args:  cobra.ExactArgs(0),
		Run: func(_ *cobra.Command, _ []string) {
			dumpExecveMap(mapFname)
		},
	}

	flags := ret.Flags()
	flags.StringVar(&mapFname, "map-fname", mapFname, "execve map filename")

	return ret
}

func policyfilterCmd() *cobra.Command {

	mapFname := filepath.Join(defaults.DefaultMapRoot, defaults.DefaultMapPrefix, policyfilter.MapName)

	ret := &cobra.Command{
		Use:   "policyfilter",
		Short: "dump policyfilter state",
		Args:  cobra.ExactArgs(0),
		Run: func(_ *cobra.Command, _ []string) {
			PolicyfilterState(mapFname)
		},
	}

	flags := ret.Flags()
	flags.StringVar(&mapFname, "map-fname", mapFname, "policyfilter map filename")

	return ret
}

func dumpExecveMap(fname string) {
	m, err := ebpf.LoadPinnedMap(fname, &ebpf.LoadPinOptions{
		ReadOnly: true,
	})
	if err != nil {
		logger.GetLogger().WithError(err).Fatal("failed to open execve map")
	}

	data := make(map[execvemap.ExecveKey]execvemap.ExecveValue)
	iter := m.Iterate()

	var key execvemap.ExecveKey
	var val execvemap.ExecveValue
	for iter.Next(&key, &val) {
		data[key] = val
	}

	if err := iter.Err(); err != nil {
		logger.GetLogger().WithError(err).Fatal("error iterating execve map")
	}

	if len(data) == 0 {
		fmt.Printf("(empty)")
		return
	}

	for k, v := range data {
		fmt.Printf("%d %+v\n", k, v)
	}
}

func dumpProcessCache() *cobra.Command {
	skipZeroRefcnt := false
	excludeExecveMapProcesses := false
	var maxCallRecvMsgSize int

	ret := &cobra.Command{
		Use: "processcache",
		// this is for legacy compatibility reason
		Aliases: []string{"processCache"},
		Short:   "dump process cache",
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := common.NewClientWithDefaultContextAndAddress()
			if err != nil {
				return fmt.Errorf("failed to create a gRPC client: %w", err)
			}

			req := tetragon.GetDebugRequest{
				Flag: tetragon.ConfigFlag_CONFIG_FLAG_DUMP_PROCESS_CACHE,
				Arg: &tetragon.GetDebugRequest_Dump{
					Dump: &tetragon.DumpProcessCacheReqArgs{
						SkipZeroRefcnt:            skipZeroRefcnt,
						ExcludeExecveMapProcesses: excludeExecveMapProcesses,
					},
				},
			}
			res, err := c.Client.GetDebug(c.Ctx, &req, grpc.MaxCallRecvMsgSize(maxCallRecvMsgSize))
			if err != nil {
				return fmt.Errorf("failed to get process dump debug info: %w", err)
			}

			if res.Flag != tetragon.ConfigFlag_CONFIG_FLAG_DUMP_PROCESS_CACHE {
				return fmt.Errorf("unexpected response flag: %s", res.Flag)
			}

			for _, p := range res.GetProcesses().Processes {
				if s, err := p.MarshalJSON(); err == nil {
					cmd.Println(string(s))
				} else {
					logger.GetLogger().WithError(err).WithField("process", p).Error("failed to marshal process")
				}
			}

			return nil
		},
	}

	flags := ret.Flags()
	flags.BoolVar(&skipZeroRefcnt, "skip-zero-refcnt", skipZeroRefcnt, "skip entries with zero refcnt")
	flags.BoolVar(&excludeExecveMapProcesses, "exclude-execve-map-processes", excludeExecveMapProcesses, "exclude processes that also exist in the execve_map")
	flags.IntVar(&maxCallRecvMsgSize, "max-recv-size", 4194304, "The maximum message size in bytes the client can receive. Default is gRPC 4MB default.")

	return ret
}

func PolicyfilterState(fname string) {
	m, err := policyfilter.OpenMap(fname)
	if err != nil {
		logger.GetLogger().WithError(err).Fatal("Failed to open policyfilter map")
		return
	}
	defer m.Close()

	data, err := m.Dump()
	if err != nil {
		logger.GetLogger().WithError(err).Fatal("Failed to open policyfilter map")
		return
	}

	fmt.Println("--- PolicyID to CgroupIDs mapping ---")

	if len(data.Policy) == 0 {
		fmt.Printf("(empty)\n")
	}

	for polId, cgIDs := range data.Policy {
		ids := make([]string, 0, len(cgIDs))
		for id := range cgIDs {
			ids = append(ids, strconv.FormatUint(uint64(id), 10))
		}
		fmt.Printf("%d: %s\n", polId, strings.Join(ids, ","))
	}

	if data.Cgroup != nil {
		fmt.Println("--- CgroupID to PolicyIDs mapping ---")

		if len(data.Cgroup) == 0 {
			fmt.Printf("(empty)\n")
		}

		for cgIDs, polIds := range data.Cgroup {
			ids := make([]string, 0, len(polIds))
			for id := range polIds {
				ids = append(ids, strconv.FormatUint(uint64(id), 10))
			}
			fmt.Printf("%d: %s\n", cgIDs, strings.Join(ids, ","))
		}
	}
}

func NamespaceState(fname string) error {
	m, err := ebpf.LoadPinnedMap(fname, &ebpf.LoadPinOptions{
		ReadOnly: true,
	})
	if err != nil {
		logger.GetLogger().WithError(err).WithField("file", fname).Warn("Could not open process tree map")
		return err
	}

	defer m.Close()

	var (
		key uint64
		val uint64
	)

	fmt.Printf("cgroupId: stableId\n")
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		fmt.Printf("%d: %d\n", key, val)
	}

	return nil
}

func bpfErrMetricsCmd() *cobra.Command {

	mapFname := filepath.Join(defaults.DefaultMapRoot, defaults.DefaultMapPrefix, errmetrics.MapName)
	var output string

	ret := &cobra.Command{
		Use:   "errmetrics",
		Short: "dump BPF error metrics",
		Args:  cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, _ []string) error {
			return ErrMetrics(mapFname, cmd.OutOrStdout(), output)
		},
	}

	flags := ret.Flags()
	flags.StringVar(&mapFname, "map-fname", mapFname, "policyfilter map filename")
	flags.StringVarP(&output, "output", "o", "tab", "Output format. One of tab or json.")

	return ret
}

func ErrMetrics(fname string, out io.Writer, output string) error {
	m, err := errmetrics.OpenMap(fname)
	if err != nil {
		return fmt.Errorf("failed to open errmetrics map: %w", err)
	}
	defer m.Close()

	ret, err := m.Dump()
	if err != nil {
		return fmt.Errorf("failed to dump errmetrics map: %w", err)
	}

	switch output {
	case "json":
		jsonOut, err := json.Marshal(ret)
		if err != nil {
			return fmt.Errorf("failed to marshal output to JSON: %w", err)
		}
		out.Write(jsonOut)
	case "tab":
		w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "Location\tError\tCount")
		for _, entry := range ret {
			fmt.Fprintf(w, "%s\t%s\t%d\n", entry.Location, entry.Error, entry.Count)
		}
		w.Flush()
	default:
		return fmt.Errorf("unknown output format: %s", output)
	}

	return nil
}
