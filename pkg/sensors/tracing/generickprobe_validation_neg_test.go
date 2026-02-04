// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
)

func TestKprobeReturnArgActionValidation(t *testing.T) {
	// ReturnArgAction validation requires kernel >= 5.3 (EnableLargeProgs)
	if !config.EnableLargeProgs() {
		t.Skip("Test requires kernel >= 5.3 for ReturnArgAction support")
	}

	// Initialize minimal configuration for testing
	logger.SetDefaultLogLevel()
	origHubbleLib := option.Config.HubbleLib
	option.Config.HubbleLib = "test data" // dummy path to bypass some checks if any
	defer func() {
		option.Config.HubbleLib = origHubbleLib
	}()

	// Create a policy with the invalid "Post" action in returnArgAction
	spec := &v1alpha1.TracingPolicySpec{
		KProbes: []v1alpha1.KProbeSpec{
			{
				Call:    "__x64_sys_close",
				Syscall: true,
				Return:  true,
				ReturnArg: &v1alpha1.KProbeArg{
					Index: 0,
					Type:  "int",
				},
				ReturnArgAction: "Post", // This should be rejected
			},
		},
	}

	// We need a dummy `addKprobeIn` structure which is internal to this package
	// Since we are in package tracing, we can define/use it.
	in := &addKprobeIn{
		policyName: "test-policy",
	}

	// Call internal addKprobe function
	_, err := addKprobe("sys_close", 0, &spec.KProbes[0], in)

	require.Error(t, err)
	require.ErrorContains(t, err, "ReturnArgAction type 'Post' is not supported for retprobes")
}
