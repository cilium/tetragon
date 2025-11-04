// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"errors"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

func getNamespaceAndSelectors(tp tracingpolicy.TracingPolicy) (string, *slimv1.LabelSelector, *slimv1.LabelSelector) {
	var namespace string
	if tpNs, ok := tp.(tracingpolicy.TracingPolicyNamespaced); ok {
		namespace = tpNs.TpNamespace()
	}

	var podSelector *slimv1.LabelSelector
	if ps := tp.TpSpec().PodSelector; ps != nil {
		if len(ps.MatchLabels)+len(ps.MatchExpressions) > 0 {
			podSelector = ps
		}
	}

	var containerSelector *slimv1.LabelSelector
	if ps := tp.TpSpec().ContainerSelector; ps != nil {
		if len(ps.MatchLabels)+len(ps.MatchExpressions) > 0 {
			containerSelector = ps
		}
	}
	return namespace, podSelector, containerSelector
}

func validateTracingPolicy(tp tracingpolicy.TracingPolicy) error {
	tpSpec := tp.TpSpec()
	if tpSpec == nil {
		return errors.New("tracing policy spec is nil")
	}

	/////////////////////////
	// Validate if the tracing policy has bindings
	/////////////////////////
	hasBindings := IsTracingPolicyTemplate(tpSpec.Options)
	if !hasBindings {
		return nil
	}

	// if the tracing policy has bindings it cannot have podSelector/containerSelector/namespace, because it is considered "a template".
	// The selectors will be applied when we deploy the TracingPolicyBinding CRs
	// This is just a basic validation we implement here to avoid falling in the global policyfilter case.
	namespace, podSelector, containerSelector := getNamespaceAndSelectors(tp)
	if namespace != "" || podSelector != nil || containerSelector != nil {
		return errors.New("podSelector, containerSelector or namespace cannot be used in a tracing policy template with bindings")
	}
	return nil
}

func getRefPolicyFromOptions(opts []v1alpha1.OptionSpec) string {
	for _, opt := range opts {
		if opt.Name == "policy-template-ref" {
			return opt.Value
		}
	}
	return ""
}

func getValuesFromOptions(opts []v1alpha1.OptionSpec) string {
	for _, opt := range opts {
		if opt.Name == "values" {
			return opt.Value
		}
	}
	return ""
}

func getBinidingFromOptions(opts []v1alpha1.OptionSpec) string {
	for _, opt := range opts {
		if opt.Name == "binding" {
			return opt.Value
		}
	}
	return ""
}

func getArgTypeFromOptions(opts []v1alpha1.OptionSpec) string {
	for _, opt := range opts {
		if opt.Name == "arg-type" {
			return opt.Value
		}
	}
	return ""
}

func isTracingPolicyBinding(opts []v1alpha1.OptionSpec) bool {
	return getRefPolicyFromOptions(opts) != "" && getBinidingFromOptions(opts) != "" && getValuesFromOptions(opts) != ""
}

func IsTracingPolicyTemplate(opts []v1alpha1.OptionSpec) bool {
	return getBinidingFromOptions(opts) != "" && getArgTypeFromOptions(opts) != ""
}
