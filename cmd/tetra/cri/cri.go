// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package cri

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
	criapi "k8s.io/cri-api/pkg/apis/runtime/v1"

	"github.com/cilium/tetragon/pkg/cri"
)

type criFlags struct {
	output   string
	endpoint string
}

func defaultFlags() *criFlags {
	return &criFlags{
		output:   "raw",
		endpoint: "",
	}
}

func New() *cobra.Command {
	flagVals := defaultFlags()
	ret := &cobra.Command{
		Use:          "cri",
		Short:        "connect to CRI",
		Hidden:       false,
		SilenceUsage: false,
	}

	ret.AddCommand(
		versionCmd(flagVals),
		cgroupPathCmd(flagVals),
	)

	flags := ret.PersistentFlags()
	flags.StringVarP(&flagVals.output, "output", "o", flagVals.output, "Output format (raw or json)")
	flags.StringVarP(&flagVals.endpoint, "runtime-endpoint", "r", flagVals.endpoint, "CRI endpoint")

	return ret
}

func versionCmd(flagVals *criFlags) *cobra.Command {
	ret := &cobra.Command{
		Use:   "version",
		Short: "retrieve CRI version",
		Args:  cobra.ExactArgs(0),
		RunE: func(_ *cobra.Command, _ []string) error {
			ctx := context.Background()
			client, err := cri.NewClient(ctx, flagVals.endpoint)
			if err != nil {
				return err
			}

			res, err := client.Version(ctx, &criapi.VersionRequest{})
			if err != nil {
				return err
			}

			switch flagVals.output {
			case "raw":
				fmt.Printf("%v\n", res)
			case "json":
				b, err := json.Marshal(res)
				if err != nil {
					return fmt.Errorf("failed to generate json: %w", err)
				}
				fmt.Println(string(b))
			}
			return nil
		},
	}
	return ret
}

func cgroupPathCmd(flagVals *criFlags) *cobra.Command {
	ret := &cobra.Command{
		Use:   "cgroup_path",
		Short: "retrieve cgroup path for container",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			ctx := context.Background()
			client, err := cri.NewClient(ctx, flagVals.endpoint)
			if err != nil {
				return err
			}

			ret, err := cri.CgroupPath(ctx, client, args[0])
			if err != nil {
				return err
			}
			fmt.Println(ret)
			return nil
		},
	}
	return ret
}
