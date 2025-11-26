// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build k8s

package policyfilter

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/cmd/tetra/common"
	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/cri"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/spf13/cobra"
)

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
				logger.GetLogger().Info("cgroup", "path", fullCgroupPath)
			}

			cgID, err := cgroups.GetCgroupIdFromPath(fullCgroupPath)
			if err != nil {
				logger.Fatal(logger.GetLogger(), "Failed to parse cgroup", logfields.Error, err)
			}

			if common.Debug {
				logger.GetLogger().Info("cgroup", "id", cgID)
			}

			m, err := policyfilter.OpenMap(mapFname)
			if err != nil {
				logger.Fatal(logger.GetLogger(), "Failed to open policyfilter map", logfields.Error, err)
				return err
			}
			defer m.Close()

			data, err := m.Dump()
			if err != nil {
				logger.Fatal(logger.GetLogger(), "Failed to dump policyfilter map", logfields.Error, err)
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
