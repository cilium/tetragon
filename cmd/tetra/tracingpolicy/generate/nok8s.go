// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !k8s

package generate

import (
	"fmt"

	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	return &cobra.Command{
		Use:   "generate",
		Short: "generate tracing policies",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return fmt.Errorf("generate command not suppported in nok8s build")
		},
	}
}
