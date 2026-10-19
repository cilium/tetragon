// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/testutils/policytest"
)

// A remote runner hands a Selection to another tetra as arguments, and the
// run flags there must parse them back into the same Selection.
func TestSelectionArgsRoundTrip(t *testing.T) {
	for name, want := range map[string]*policytest.Selection{
		"names": {
			Names:  []string{"kprobe-lseek", "uprobe-generic"},
			Params: map[string]string{},
		},
		"all": {
			Names:       []string{},
			AllTests:    true,
			AllParams:   true,
			MonitorMode: true,
			Params:      map[string]string{},
		},
		"params": {
			Names:  []string{"kprobe-fd-arg"},
			Params: map[string]string{"fd": "3", "path": "/tmp/a=b"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			var f selectionFlags
			flags := pflag.NewFlagSet("run", pflag.ContinueOnError)
			f.register(flags)
			require.NoError(t, flags.Parse(want.Args()))
			require.Equal(t, want, f.selection(flags.Args()))
		})
	}
}
