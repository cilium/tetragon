// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package common

import (
	"github.com/spf13/cobra"
)

func AddSubCommandIfNotNil(parent *cobra.Command, cmds ...*cobra.Command) {
	var newCmds []*cobra.Command
	for _, cmd := range cmds {
		if cmd != nil {
			newCmds = append(newCmds, cmd)
		}
	}
	parent.AddCommand(newCmds...)
}
