// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !k8s

package policyfilter

import "github.com/spf13/cobra"

func listPoliciesForContainer() *cobra.Command {
	return nil
}
