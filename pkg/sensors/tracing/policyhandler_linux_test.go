// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/policyfilter"
)

func TestNewPolicyInfoRejectsNamespacedRegisterOverride(t *testing.T) {
	spec := &v1alpha1.TracingPolicySpec{
		UProbes: []v1alpha1.UProbeSpec{{
			Path:    "/procRoot/1/root/usr/lib/x86_64-linux-gnu/libc.so.6",
			Symbols: []string{"mount"},
			Selectors: []v1alpha1.KProbeSelector{{
				MatchActions: []v1alpha1.ActionSelector{{
					Action:  "Override",
					ArgRegs: []string{"rip=-901776%rip", "rsp=0%rsp"},
				}},
			}},
		}},
	}

	// A namespaced (tenant-writable) policy must not carry the register-write
	// Override primitive.
	_, err := newPolicyInfoFromSpec("tenant", "reg-override", policyfilter.NoFilterID, spec, nil)
	require.ErrorIs(t, err, errNamespacedRegisterOverride)

	// The same spec is allowed for a cluster-wide policy (empty namespace).
	_, err = newPolicyInfoFromSpec("", "reg-override", policyfilter.NoFilterID, spec, nil)
	require.NoError(t, err)
}

func TestNewPolicyInfoAllowsNamespacedUprobeWithoutArgRegs(t *testing.T) {
	spec := &v1alpha1.TracingPolicySpec{
		UProbes: []v1alpha1.UProbeSpec{{
			Path:    "/bin/bash",
			Symbols: []string{"main"},
		}},
	}
	_, err := newPolicyInfoFromSpec("tenant", "plain-uprobe", policyfilter.NoFilterID, spec, nil)
	require.NoError(t, err)
}
