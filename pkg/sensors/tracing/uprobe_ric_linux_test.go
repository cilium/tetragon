// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package tracing

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
)

// Validation requires the pod handlers the agent wires at startup; tests build
// policies without that wiring, so install an empty lister by default.
func init() {
	ricPods.listPods = func() ([]*v1.Pod, error) { return nil, nil }
}

// setPodLister installs a pod lister for one test.
func setPodLister(t *testing.T, listPods func() ([]*v1.Pod, error)) {
	t.Helper()
	ricPods.Lock()
	previous := ricPods.listPods
	ricPods.listPods = listPods
	ricPods.Unlock()
	t.Cleanup(func() {
		ricPods.Lock()
		ricPods.listPods = previous
		ricPods.Unlock()
	})
}

// selectorMatcher for a namespaced policy only matches pods in that namespace,
// mirroring policyfilter: a label-only selector must not attach across
// namespaces. A cluster-wide policy matches any namespace.
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

func TestResolvePathInContainerLifecycleHooks(t *testing.T) {
	spec := &v1alpha1.TracingPolicySpec{
		PodSelector: &slimv1.LabelSelector{},
		UProbes: []v1alpha1.UProbeSpec{{
			Path:                   "/usr/bin/app",
			Symbols:                []string{"main"},
			ResolvePathInContainer: true,
		}},
	}
	polInfo, err := newPolicyInfoFromSpec("ns", "lifecycle", policyfilter.PolicyID(8), spec, nil)
	require.NoError(t, err)
	closedFiles := false
	parent := &sensors.Sensor{
		Name: "generic_uprobe", Policy: polInfo.name, Namespace: polInfo.namespace,
		PostLoadHook: func() error { closedFiles = true; return nil },
	}

	setupResolvePathInContainer(parent, spec, polInfo)

	require.Len(t, parent.Maps, 2,
		"the parent must own the policy maps its children reference")
	require.NotNil(t, parent.PreUnloadHook,
		"children must be torn down before the parent unloads its policy maps")
	require.Nil(t, parent.PostUnloadHook,
		"child cleanup must complete before parent policy maps are unloaded")

	// The container attach is composed onto the hook the caller already set,
	// rather than replacing it.
	require.NoError(t, parent.PostLoadHook())
	require.True(t, closedFiles, "the existing post-load hook must still run")
	// Leave no registration behind for the other tests.
	require.NoError(t, parent.PreUnloadHook())
}

// A policy with no resolvePathInContainer uprobe is left alone.
func TestResolvePathInContainerSkipsRegularPolicy(t *testing.T) {
	spec := &v1alpha1.TracingPolicySpec{
		UProbes: []v1alpha1.UProbeSpec{{Path: "/bin/app", Symbols: []string{"main"}}},
	}
	polInfo, err := newPolicyInfoFromSpec("", "regular", policyfilter.PolicyID(9), spec, nil)
	require.NoError(t, err)
	parent := &sensors.Sensor{Name: "generic_uprobe"}

	setupResolvePathInContainer(parent, spec, polInfo)

	require.Nil(t, parent.PostLoadHook)
	require.Nil(t, parent.PreUnloadHook)
	require.Empty(t, parent.Maps)
}

// The initial attach set comes from the informer: only running containers of
// pods the policy selects, keyed by the pod's own UID.
func TestRunningContainerKeys(t *testing.T) {
	selected := labeledPod("uid-1", "ns", map[string]string{"app": "sshd"}, "abc")
	// a second container that is not running must not be claimed.
	selected.Status.ContainerStatuses = append(selected.Status.ContainerStatuses, v1.ContainerStatus{
		ContainerID: "containerd://stopped",
		State:       v1.ContainerState{Terminated: &v1.ContainerStateTerminated{}},
	})
	other := labeledPod("uid-2", "ns", map[string]string{"app": "nginx"}, "def")
	setPodLister(t, func() ([]*v1.Pod, error) { return []*v1.Pod{selected, other}, nil })

	match := func(ns string, lbls map[string]string) bool { return ns == "ns" && lbls["app"] == "sshd" }
	require.Equal(t, []string{"uid-1/abc"}, runningContainerKeys(match))
}

// A failed listing must not be treated as an empty cluster.
func TestRunningContainerKeysListFailure(t *testing.T) {
	setPodLister(t, func() ([]*v1.Pod, error) { return nil, errors.New("cache not synced") })
	require.Empty(t, runningContainerKeys(matchAllPods))
}

func TestPreValidateUprobesRequiresPodHandlers(t *testing.T) {
	setPodLister(t, nil)

	require.ErrorIs(t, preValidateUprobes(ricSpec()), errRICNoPodHandlers,
		"a resolvePathInContainer policy must not load where no pod event can drive it")
	require.NoError(t, preValidateUprobes(&v1alpha1.TracingPolicySpec{
		UProbes: []v1alpha1.UProbeSpec{{Path: "/bin/app", Symbols: []string{"main"}}},
	}), "regular uprobes do not need the pod handlers")
}
