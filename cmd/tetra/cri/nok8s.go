// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !k8s

package cri

import "github.com/spf13/cobra"

func New() *cobra.Command {
	return nil
}
