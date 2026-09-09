// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracingpolicy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDomainsOutputFlag(t *testing.T) {
	for _, output := range []string{"text", "json"} {
		t.Run(output, func(t *testing.T) {
			cmd := tpListDomainsCmd()
			require.NoError(t, cmd.ParseFlags([]string{"--output", output}))
		})
	}

	cmd := tpListDomainsCmd()
	err := cmd.ParseFlags([]string{"--output", "yaml"})
	require.ErrorContains(t, err, "please provide one of (text, json)")
}
