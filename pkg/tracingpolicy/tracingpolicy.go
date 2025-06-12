// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracingpolicy

import (
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

// TracingPolicy is a tracing policy interface.
// It is implemented by v1alpha1.types.TracingPolicy and
// config.GenericTracingConf. The former is what is the k8s API server uses,
// and the latter is used when we load files directly (e.g., via the cli).
type TracingPolicy interface {
	// TpName returns the name of the policy.
	TpName() string
	// TpSpec  returns the specification of the policy
	TpSpec() *v1alpha1.TracingPolicySpec
	// TpInfo returns a description of the policy
	TpInfo() string
}

// revive:disable:exported

// TracingPolicyNamespaced is an interface for tracing policy applied on a specific namespace
type TracingPolicyNamespaced interface {
	TracingPolicy
	// TpNamespace returns the namespace of the policy
	TpNamespace() string
}

// revive:enable:exported

type PolicyInfo struct {
	Name string
	Hook string
}

type PolicyEvent interface {
	PolicyInfo() PolicyInfo
}

// TpLongname returns a long name of a tracing policy:
// name if the policy is not namespaced, or namespace/name if it is
func TpLongname(tp TracingPolicy) string {
	name := tp.TpName()
	if tpns, ok := tp.(TracingPolicyNamespaced); ok {
		name = tpns.TpNamespace() + "/" + name
	}
	return name
}
