// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policyfilter

import (
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/cilium/tetragon/cmd/tetra/debug"
	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/policyfilter"
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
	)

	listPolCmd := listPoliciesForContainer()
	if listPolCmd != nil {
		ret.AddCommand(listPolCmd)
	}

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
				logger.Fatal(logger.GetLogger(), "Failed to parse cgroup", logfields.Error, err)
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
				logger.Fatal(logger.GetLogger(), "Failed to parse policy id", logfields.Error, err)
			}
			polID := policyfilter.PolicyID(x)

			var cgID uint64
			switch argType {
			case "file":
				cgID, err = cgroups.GetCgroupIdFromPath(args[1])
			case "id":
				cgID, err = strconv.ParseUint(args[1], 10, 32)
			default:
				logger.Fatal(logger.GetLogger(), "Unknown type", "type", argType)
			}

			if err != nil {
				logger.Fatal(logger.GetLogger(), "Failed to parse cgroup", logfields.Error, err)
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
		logger.Fatal(logger.GetLogger(), "Failed to open policyfilter map", logfields.Error, err)
		return
	}
	defer m.Close()

	err = m.AddCgroup(polID, cgID)
	if err != nil {
		logger.Fatal(logger.GetLogger(), "Failed to add cgroup id", logfields.Error, err)
	}

}
