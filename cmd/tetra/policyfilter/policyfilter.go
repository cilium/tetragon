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

			policyIds, ok := data.Cgroup[policyfilter.CgroupID(cgID)]
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

			common.PrintTracingPolicies(os.Stdout, res.Policies, func(pol *tetragon.TracingPolicyStatus) bool {
				_, ok := policyIds[policyfilter.PolicyID(pol.FilterId)]
				return !ok
			})

			return nil
		},
	}

	flags := ret.Flags()
	flags.StringVarP(&endpoint, "runtime-endpoint", "r", "", "CRI endpoint")
	flags.StringVar(&mapFname, "map-fname", mapFname, "policyfilter map filename")
	flags.StringVar(&cgroupMnt, "cgroup-mount", cgroupMnt, "cgroupFS mount point")
	return ret
}
