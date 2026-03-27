// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !k8s

package tracingpolicy

import (
	"encoding/json"
	"fmt"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/nok8s"
)

// FromYAML parses a YAML string into a TracingPolicy -- !k8s version
func FromYAML(data string) (TracingPolicy, error) {
	kind, jsonBytes, err := nok8s.ParseK8sObj(data)
	if err != nil {
		return nil, err
	}

	switch kind {
	case v1alpha1.TPKindDefinition:
		var gtp GenericTracingPolicy
		if err := json.Unmarshal(jsonBytes, &gtp); err != nil {
			return nil, fmt.Errorf("failed to unmarshal TracingPolicy: %w", err)
		}
		return &gtp, nil
	case v1alpha1.TPNamespacedKindDefinition:
		return nil, fmt.Errorf("namespaced tracing policies not supported in non-k8s builds: %s", kind)
	default:
		return nil, fmt.Errorf("unknown kind: %s", kind)
	}
}
