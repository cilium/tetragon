// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package dump

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/cmd/tetra/common"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/cilium/tetragon/pkg/sensors/exec/execvemap"
	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	ret := &cobra.Command{
		Use:          "dump",
		Short:        "dump information",
		Hidden:       true,
		SilenceUsage: true,
	}

	ret.AddCommand(
		execveMapCmd(),
		policyfilterCmd(),
		dumpProcessCache(),
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
						SkipZeroRefcnt: skipZeroRefcnt,
					},
				},
			}
			res, err := c.Client.GetDebug(c.Ctx, &req)
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

	if len(data) == 0 {
		fmt.Printf("(empty)\n")
		return
	}

	for polId, cgIDs := range data {
		ids := make([]string, 0, len(cgIDs))
		for id := range cgIDs {
			ids = append(ids, strconv.FormatUint(uint64(id), 10))
		}
		fmt.Printf("%d: %s\n", polId, strings.Join(ids, ","))
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
