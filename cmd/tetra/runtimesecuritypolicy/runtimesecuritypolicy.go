// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package runtimesecuritypolicy

import (
	"os"

	"github.com/cilium/tetragon/pkg/runtimesecuritypolicy"
	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"
)

func New() *cobra.Command {
	return &cobra.Command{
		Use:     "runtimesecuritypolicy",
		Aliases: []string{"rspolicy"},
		Hidden:  true,
		Short:   "Convert RuntimeSecurityPolicy to TracingPolicy. Development tool.",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fileContent, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			policy, err := runtimesecuritypolicy.FromYAML(fileContent)
			if err != nil {
				return err
			}

			tracingPolicy, err := runtimesecuritypolicy.ToTracingPolicy(*policy)
			if err != nil {
				return err
			}
			tpYAML, _ := yaml.Marshal(tracingPolicy)
			cmd.Println(string(tpYAML))
			return nil
		},
	}
}
