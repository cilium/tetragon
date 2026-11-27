// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && nok8s

package policytest

import "github.com/spf13/cobra"

// tetra built without Kubernetes support has no k8s-run
func addK8sRunCmd(*cobra.Command) {}
