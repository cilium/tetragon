// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"path/filepath"
	"time"
)

// TestConf is the runtime configuration for a single policy test
type TestConf struct {
	MonitorMode bool
	ParamValues map[string]any
}

// Conf is the runtime configuration for a sequence of policy tests
type Conf struct {
	// Test Binaries directory
	BinsDir string
	// Agent GRPC address
	GrpcAddr string

	// configuration for the current test
	TestConf *TestConf

	// Path to save the generated policy
	DumpPolicyPath string

	// Namespace, when set, scopes the generated policy to a namespaced
	// TracingPolicyNamespaced in this namespace. Empty means the policy is
	// applied cluster-scoped (the local case).
	Namespace string

	// PodSelectorLabels, when non-empty, constrains the generated policy to pods
	// matching these labels (injected as spec.podSelector). Empty means no
	// selector is applied (the local case).
	PodSelectorLabels map[string]string

	// Timeout bounds the gRPC client session (the event stream plus the
	// per-policy RPCs), which all share one deadline. It must cover the whole
	// run, since every requested test is loaded/triggered/checked in sequence.
	// Zero uses DefaultTimeout.
	Timeout time.Duration
}

// DefaultTimeout is the gRPC session timeout used when Conf.Timeout is unset.
// It must comfortably cover a run of many tests in sequence.
const DefaultTimeout = 10 * time.Minute

func (c *Conf) TestBinary(s string) string {
	return filepath.Join(c.BinsDir, s)
}

// PodScoped reports whether the generated policy should be namespaced and
// constrained to a pod via a podSelector (the Kubernetes in-pod case). When
// false, the policy is applied cluster-scoped with no selector (the local
// case). Both a namespace and pod selector labels are required for scoping.
func (c *Conf) PodScoped() bool {
	return c.Namespace != "" && len(c.PodSelectorLabels) > 0
}
