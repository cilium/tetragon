// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !k8s

package tracingpolicy

import (
	"encoding/json"
	"fmt"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"gopkg.in/yaml.v2"
)

// yamlToJSON converts YAML to JSON bytes.
// This is needed because our structs have json tags but not yaml tags.
func yamlToJSON(yamlBytes []byte) ([]byte, error) {
	var data interface{}
	if err := yaml.Unmarshal(yamlBytes, &data); err != nil {
		return nil, err
	}
	// Convert map[interface{}]interface{} to map[string]interface{}
	data = convertMapKeys(data)
	return json.Marshal(data)
}

// convertMapKeys recursively converts map[interface{}]interface{} to map[string]interface{}
// which is required for JSON marshaling.
func convertMapKeys(v interface{}) interface{} {
	switch x := v.(type) {
	case map[interface{}]interface{}:
		m := make(map[string]interface{})
		for k, val := range x {
			m[fmt.Sprintf("%v", k)] = convertMapKeys(val)
		}
		return m
	case []interface{}:
		for i, val := range x {
			x[i] = convertMapKeys(val)
		}
		return x
	default:
		return v
	}
}

// kindDetector is a minimal struct to detect the Kind field from YAML
type kindDetector struct {
	Kind string `json:"kind"`
}

// FromYAML parses a YAML string into a TracingPolicy
func FromYAML(data string) (TracingPolicy, error) {
	// Convert YAML to JSON (needed because structs have json tags, not yaml tags)
	jsonBytes, err := yamlToJSON([]byte(data))
	if err != nil {
		return nil, fmt.Errorf("failed to convert YAML to JSON: %w", err)
	}

	// Detect the kind
	var kd kindDetector
	if err := json.Unmarshal(jsonBytes, &kd); err != nil {
		return nil, fmt.Errorf("failed to detect kind: %w", err)
	}

	switch kd.Kind {
	case v1alpha1.TPKindDefinition:
		var gtp GenericTracingPolicy
		if err := json.Unmarshal(jsonBytes, &gtp); err != nil {
			return nil, fmt.Errorf("failed to unmarshal TracingPolicy: %w", err)
		}
		return &gtp, nil
	case v1alpha1.TPNamespacedKindDefinition:
		var gtp GenericTracingPolicyNamespaced
		if err := json.Unmarshal(jsonBytes, &gtp); err != nil {
			return nil, fmt.Errorf("failed to unmarshal TracingPolicyNamespaced: %w", err)
		}
		return &gtp, nil
	default:
		return nil, fmt.Errorf("unknown kind: %s", kd.Kind)
	}
}
