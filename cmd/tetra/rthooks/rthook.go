// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package rthooks

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/cmd/tetra/common"
)

type addContainerConf struct {
	containerID string
	rootDir     string
	annotations map[string]string
}

func New() *cobra.Command {
	ret := &cobra.Command{
		Use:          "rthooks",
		Short:        "trigger runtime hooks (for testing/debugging)",
		Hidden:       true,
		SilenceUsage: true,
	}

	cnf := addContainerConf{}
	add := &cobra.Command{
		Use:   "create-container --container-id=<containerID> --root-dir=<rootDir>",
		Short: "trigger create-container hook",
		RunE: func(_ *cobra.Command, _ []string) error {
			c, err := common.NewClientWithDefaultContextAndAddress()
			if err != nil {
				return fmt.Errorf("failed to create gRPC client: %w", err)
			}
			defer c.Close()

			req := &tetragon.RuntimeHookRequest{
				Event: &tetragon.RuntimeHookRequest_CreateContainer{
					CreateContainer: &tetragon.CreateContainer{
						CgroupsPath: cnf.containerID,
						RootDir:     cnf.rootDir,
						Annotations: cnf.annotations,
					},
				},
			}

			_, err = c.Client.RuntimeHook(c.Ctx, req)
			if err != nil {
				return fmt.Errorf("failed to trigger create-container hook: %w", err)
			}
			return nil
		},
	}

	flags := add.Flags()
	flags.StringVar(&cnf.containerID, "container-id", "", "container directory")
	flags.StringVar(&cnf.rootDir, "root-dir", "", "container root directory")
	flags.StringToStringVar(&cnf.annotations, "annotations", map[string]string{}, "container annotations")

	ret.AddCommand(add)
	return ret
}
