// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

func TestUprobeEventConfigCarriesPolicyID(t *testing.T) {
	var state uprobeConfigState
	err := initUprobeArgs(&v1alpha1.UProbeSpec{}, &uprobeHas{}, &addUprobeIn{policyID: 7}, &state)
	require.NoError(t, err)
	require.Equal(t, uint32(7), state.eventConfig.PolicyID)
}
