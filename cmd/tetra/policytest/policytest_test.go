// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBinDirRequired(t *testing.T) {
	for _, args := range [][]string{
		{"run", ".*"},
		{"run-multi", ".*"},
		{"dump-policy", ".*"},
	} {
		t.Run(args[0], func(t *testing.T) {
			cmd := New()
			cmd.SetArgs(args)
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			err := cmd.Execute()
			require.ErrorContains(t, err, "--bindir is required")
		})
	}
}
