// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPreparePolicy(t *testing.T) {
	policyTest := &T{
		Name:   "test",
		Policy: func(_ *Conf) (Policy, error) { return Policy(clusterScopedPolicy), nil },
	}
	noPolicyTest := &T{
		Name:   "nopolicy",
		Policy: func(_ *Conf) (Policy, error) { return Policy(""), nil },
	}

	t.Run("local case is cluster-scoped", func(t *testing.T) {
		pol, name, ns, err := preparePolicy(&Conf{}, policyTest)
		require.NoError(t, err)
		assert.NotEmpty(t, pol)
		assert.Equal(t, "test-policy", name)
		assert.Empty(t, ns, "local policy must be cluster-scoped")
	})

	t.Run("k8s case is namespaced", func(t *testing.T) {
		conf := &Conf{
			Namespace:         "test-ns",
			PodSelectorLabels: map[string]string{"app": "policytest"},
		}
		pol, name, ns, err := preparePolicy(conf, policyTest)
		require.NoError(t, err)
		assert.Contains(t, string(pol), "TracingPolicyNamespaced")
		assert.Equal(t, "test-policy", name)
		assert.Equal(t, "test-ns", ns)
	})

	t.Run("test with no policy", func(t *testing.T) {
		pol, _, _, err := preparePolicy(&Conf{}, noPolicyTest)
		require.NoError(t, err)
		assert.Empty(t, pol)
	})
}
