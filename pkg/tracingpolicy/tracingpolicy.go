// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracingpolicy

import (
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

// TracingPolicy is an interface for a tracing policy
// This is implemented by v1alpha1.types.TracingPolicy and
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
