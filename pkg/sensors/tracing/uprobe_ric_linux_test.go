// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package tracing

import (
	"testing"

	"github.com/stretchr/testify/require"

	slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"
)

// selectorMatcher for a namespaced policy (policyNamespace != "") only matches
// pods in that namespace, mirroring policyfilter — a label-only selector must
// not attach across namespaces. A cluster-wide policy ("") matches any namespace.
func TestSelectorMatcherNamespaceScoping(t *testing.T) {
	sel := &slimv1.LabelSelector{MatchLabels: map[string]string{"app": "sshd"}}
	lbls := map[string]string{"app": "sshd"}

	nsScoped := selectorMatcher("prod", sel)
	require.True(t, nsScoped("prod", lbls), "must match its own namespace")
	require.False(t, nsScoped("dev", lbls), "must not match another namespace")

	clusterWide := selectorMatcher("", sel)
	require.True(t, clusterWide("prod", lbls))
	require.True(t, clusterWide("dev", lbls))

	// a nil selector matches all pods in scope, but a namespaced policy still
	// confines to its namespace.
	nsAll := selectorMatcher("prod", nil)
	require.True(t, nsAll("prod", nil))
	require.False(t, nsAll("dev", nil))
}
