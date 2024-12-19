// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policyfilter

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/cmd/tetra/common"
	"github.com/cilium/tetragon/cmd/tetra/debug"
	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/cri"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	ret := &cobra.Command{
		Use:          "policyfilter",
		Short:        "manage policyfilter map (only for debugging)",
		Hidden:       true,
		SilenceUsage: true,
	}

	ret.AddCommand(
		dumpCmd(),
		addCommand(),
		cgroupGetIDCommand(),
		dumpDebugCmd(),
		listPoliciesForContainer(),
	)

	return ret
}

func dumpDebugCmd() *cobra.Command {
	mapFname := filepath.Join(defaults.DefaultMapRoot, defaults.DefaultMapPrefix, policyfilter.CgrpNsMapName)
	ret := &cobra.Command{
		Use:   "dumpcgrp",
		Short: "dump cgroup ID to namespace state",
		Args:  cobra.ExactArgs(0),
		Run: func(_ *cobra.Command, _ []string) {
			debug.NamespaceState(mapFname)
		},
	}

	flags := ret.Flags()
	flags.StringVar(&mapFname, "map-fname", mapFname, "policyfilter map filename")
	return ret
}

func cgroupGetIDCommand() *cobra.Command {
	mapFname := filepath.Join(defaults.DefaultMapRoot, defaults.DefaultMapPrefix, policyfilter.MapName)
	ret := &cobra.Command{
		Use:   "cgroupid",
		Short: "retrieve cgroup id from file",
		Args:  cobra.ExactArgs(1),
		Run: func(_ *cobra.Command, args []string) {
			cgID, err := cgroups.GetCgroupIdFromPath(args[0])
			if err != nil {
				logger.GetLogger().WithError(err).Fatal("Failed to parse cgroup")
			}
			fmt.Printf("%d\n", cgID)
		},
	}

	flags := ret.Flags()
	flags.StringVar(&mapFname, "map-fname", mapFname, "policyfilter map filename")
	return ret
}

func dumpCmd() *cobra.Command {
	mapFname := filepath.Join(defaults.DefaultMapRoot, defaults.DefaultMapPrefix, policyfilter.MapName)
	ret := &cobra.Command{
		Use:   "dump",
		Short: "dump policyfilter state",
		Args:  cobra.ExactArgs(0),
		Run: func(_ *cobra.Command, _ []string) {
			debug.PolicyfilterState(mapFname)
		},
	}

	flags := ret.Flags()
	flags.StringVar(&mapFname, "map-fname", mapFname, "policyfilter map filename")
	return ret
}

func addCommand() *cobra.Command {
	var argType string
	mapFname := filepath.Join(defaults.DefaultMapRoot, defaults.DefaultMapPrefix, policyfilter.MapName)
	ret := &cobra.Command{
		Use:   "add [policy id] [cgroup]",
		Short: "add policyfilter entry",
		Args:  cobra.ExactArgs(2),
		Run: func(_ *cobra.Command, args []string) {
			x, err := strconv.ParseUint(args[0], 10, 32)
			if err != nil {
				logger.GetLogger().WithError(err).Fatal("Failed to parse policy id")
			}
			polID := policyfilter.PolicyID(x)

			var cgID uint64
			switch argType {
			case "file":
				cgID, err = cgroups.GetCgroupIdFromPath(args[1])
			case "id":
				cgID, err = strconv.ParseUint(args[1], 10, 32)
			default:
				logger.GetLogger().WithField("type", argType).WithError(err).Fatal("Unknown type")
			}

			if err != nil {
				logger.GetLogger().WithError(err).Fatal("Failed to parse cgroup")
			}

			addCgroup(mapFname, polID, policyfilter.CgroupID(cgID))
		},
	}

	flags := ret.Flags()
	flags.StringVar(&argType, "arg-type", "file", "cgroup type (id,file)")
	flags.StringVar(&mapFname, "map-fname", mapFname, "policyfilter map filename")
	return ret
}

func addCgroup(fname string, polID policyfilter.PolicyID, cgID policyfilter.CgroupID) {
	m, err := policyfilter.OpenMap(fname)
	if err != nil {
		logger.GetLogger().WithError(err).Fatal("Failed to open policyfilter map")
		return
	}
	defer m.Close()

	err = m.AddCgroup(polID, cgID)
	if err != nil {
		logger.GetLogger().WithError(err).Fatal("Failed to add cgroup id")
	}

}

func listPoliciesForContainer() *cobra.Command {
	var endpoint, cgroupMnt string
	mapFname := filepath.Join(defaults.DefaultMapRoot, defaults.DefaultMapPrefix, policyfilter.MapName)
	ret := &cobra.Command{
		Use:   "listpolicies [container id]",
		Short: "list all Kubernetes Identity Aware policies that apply to a specific container",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			ctx := context.Background()
			client, err := cri.NewClient(ctx, endpoint)
			if err != nil {
				return err
			}

			cgroupPath, err := cri.CgroupPath(ctx, client, args[0])
			if err != nil {
				return err
			}

			if cgroupMnt == "" {
				cgroupMnt = defaults.Cgroup2Dir
			}
			fullCgroupPath := path.Join(cgroupMnt, cgroupPath)
			if common.Debug {
				logger.GetLogger().WithField("path", fullCgroupPath).Info("cgroup")
			}

			cgID, err := cgroups.GetCgroupIdFromPath(fullCgroupPath)
			if err != nil {
				logger.GetLogger().WithError(err).Fatal("Failed to parse cgroup")
			}

			if common.Debug {
				logger.GetLogger().WithField("id", cgID).Info("cgroup")
			}

			m, err := policyfilter.OpenMap(mapFname)
			if err != nil {
				logger.GetLogger().WithError(err).Fatal("Failed to open policyfilter map")
				return err
			}
			defer m.Close()

			data, err := m.Dump()
			if err != nil {
				logger.GetLogger().WithError(err).Fatal("Failed to open policyfilter map")
				return err
			}

			policyIds, ok := data.Reverse[policyfilter.CgroupID(cgID)]
			if !ok {
				return nil
			}

			c, err := common.NewClientWithDefaultContextAndAddress()
			if err != nil {
				return fmt.Errorf("failed create gRPC client: %w", err)
			}
			defer c.Close()

			res, err := c.Client.ListTracingPolicies(c.Ctx, &tetragon.ListTracingPoliciesRequest{})
			if err != nil || res == nil {
				return fmt.Errorf("failed to list tracing policies: %w", err)
			}

			// tabwriter config imitates kubectl default output, i.e. 3 spaces padding
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "ID\tNAME\tSTATE\tFILTERID\tNAMESPACE\tSENSORS\tKERNELMEMORY")

			for _, pol := range res.Policies {
				namespace := pol.Namespace
				if namespace == "" {
					namespace = "(global)"
				}

				sensors := strings.Join(pol.Sensors, ",")

				// From v0.11 and before, enabled, filterID and error were
				// bundled in a string. To have a retro-compatible tetra
				// command, we scan the string. If the scan fails, it means
				// something else might be in Info and we print it.
				//
				// we can drop the following block (and comment) when we
				// feel tetra should support only version after v0.11
				if pol.Info != "" {
					var parsedEnabled bool
					var parsedFilterID uint64
					var parsedError string
					var parsedName string
					str := strings.NewReader(pol.Info)
					_, err := fmt.Fscanf(str, "%253s enabled:%t filterID:%d error:%512s", &parsedName, &parsedEnabled, &parsedFilterID, &parsedError)
					if err == nil {
						if parsedEnabled {
							pol.State = tetragon.TracingPolicyState_TP_STATE_ENABLED
						}
						pol.FilterId = parsedFilterID
						pol.Error = parsedError
						pol.Info = ""
					}
				}

				if _, ok := policyIds[policyfilter.PolicyID(pol.FilterId)]; !ok {
					continue
				}

				fmt.Fprintf(w, "%d\t%s\t%s\t%d\t%s\t%s\t%s\t\n",
					pol.Id,
					pol.Name,
					strings.TrimPrefix(strings.ToLower(pol.State.String()), "tp_state_"),
					pol.FilterId,
					namespace,
					sensors,
					common.HumanizeByteCount(int(pol.KernelMemoryBytes)),
				)
			}
			w.Flush()

			return nil
		},
	}

	flags := ret.Flags()
	flags.StringVarP(&endpoint, "runtime-endpoint", "r", "", "CRI endpoint")
	flags.StringVar(&mapFname, "map-fname", mapFname, "policyfilter map filename")
	flags.StringVar(&cgroupMnt, "cgroup-mount", cgroupMnt, "cgroupFS mount point")
	return ret
}
