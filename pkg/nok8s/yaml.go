// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package nok8s

import (
	"encoding/json"
	"errors"
	"fmt"

	"go.yaml.in/yaml/v3"
)

// Helpers to parse YAML files for K8s API objects, without the k8s libraries.
// Meant for !k8s builds, but not constrained there so that we can have some testing by default.
// For k8s builds, we still prefer the k8s versions because they offer validation.

// yamlToJSON converts YAML to JSON bytes.
// This is needed because our structs have json tags but not yaml tags.
func yamlToJSON(yamlBytes []byte) ([]byte, error) {
	var data any
	if err := yaml.Unmarshal(yamlBytes, &data); err != nil {
		return nil, err
	}
	return json.Marshal(data)
}

// kindDetector is a minimal struct to detect the Kind field from YAML
type kindDetector struct {
	Kind string `json:"kind"`
}

func ParseK8sObj(data string) (kind string, jsonBytes []byte, err error) {
	// Convert YAML to JSON (needed because structs have json tags, not yaml tags)
	jsonBytes, err = yamlToJSON([]byte(data))
	if err != nil {
		return
	}

	// Detect the kind
	var kd kindDetector
	if err = json.Unmarshal(jsonBytes, &kd); err != nil {
		err = fmt.Errorf("failed to detect kind: %w", err)
		return
	}

	if kd.Kind == "" {
		return "", nil, errors.New("empty kind field")
	}

	kind = kd.Kind
	return
}
