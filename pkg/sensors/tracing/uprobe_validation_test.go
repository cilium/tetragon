// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/testutils"
)

func TestUprobeEventConfigCarriesPolicyID(t *testing.T) {
	spec := &v1alpha1.UProbeSpec{
		Path:    testutils.RepoRootPath("contrib/tester-progs/uprobe-test-1"),
		Symbols: []string{"main"},
	}

	ids, err := addUprobe(spec, nil, &addUprobeIn{policyID: 7})
	require.NoError(t, err)
	require.NotEmpty(t, ids)

	for _, id := range ids {
		uprobeEntry, err := genericUprobeTableGet(id)
		require.NoError(t, err)
		require.Equal(t, uint32(7), uprobeEntry.config.PolicyID)
	}
}
