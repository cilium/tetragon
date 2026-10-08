// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

const kprobePolicy = `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "lseek-test"
spec:
  kprobes:
  - call: "sys_lseek"
    syscall: true
`

func TestInjectPodSelector(t *testing.T) {
	tp, err := tracingpolicy.FromYAML(kprobePolicy)
	require.NoError(t, err)
	out, err := injectPodSelector(tp, map[string]string{"app": "policytest"})
	require.NoError(t, err)

	tp, err = tracingpolicy.FromYAML(string(out))
	require.NoError(t, err)
	require.NotNil(t, tp.TpSpec().PodSelector)
	assert.Equal(t, "policytest", tp.TpSpec().PodSelector.MatchLabels["app"])
	assert.Equal(t, "lseek-test", tp.TpName())
	require.Len(t, tp.TpSpec().KProbes, 1)
	assert.Equal(t, "sys_lseek", tp.TpSpec().KProbes[0].Call)
}
