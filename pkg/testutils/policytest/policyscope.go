// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"errors"
	"fmt"

	"sigs.k8s.io/yaml"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

var errPolicyNoSpec = errors.New("policy YAML has no spec")

// ScopePolicy rewrites a generated cluster-scoped TracingPolicy into a
// namespaced TracingPolicyNamespaced constrained to a pod via a podSelector,
// using the namespace and pod selector labels from c.
//
// When c is not PodScoped() (the local case), the policy is returned unchanged.
// The generated policy templates are left untouched: scoping is applied here, by
// post-processing the rendered YAML.
func ScopePolicy(c *Conf, pol Policy) (Policy, error) {
	if !c.PodScoped() {
		return pol, nil
	}

	var obj map[string]any
	if err := yaml.Unmarshal([]byte(pol), &obj); err != nil {
		return "", fmt.Errorf("failed to parse policy YAML: %w", err)
	}

	obj["kind"] = v1alpha1.TPNamespacedKindDefinition

	meta, ok := obj["metadata"].(map[string]any)
	if !ok {
		meta = map[string]any{}
		obj["metadata"] = meta
	}
	meta["namespace"] = c.Namespace

	spec, ok := obj["spec"].(map[string]any)
	if !ok {
		return "", errPolicyNoSpec
	}
	spec["podSelector"] = map[string]any{"matchLabels": c.PodSelectorLabels}

	out, err := yaml.Marshal(obj)
	if err != nil {
		return "", fmt.Errorf("failed to marshal scoped policy: %w", err)
	}
	return Policy(out), nil
}
