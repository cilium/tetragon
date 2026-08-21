// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build nok8s

package tracingpolicy

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/nok8s"
)

const tpURL = "file:///tracingpolicy"

var (
	//go:embed schemas/tracingpolicy-cilium.io.json
	tracingpolicyJSONSchema []byte
	tpSchema                *jsonschema.Schema
)

type memLoader struct{}

func (m *memLoader) Load(url string) (any, error) {
	switch url {
	case tpURL:
		return bytesToMap(tracingpolicyJSONSchema)
	}
	return nil, fmt.Errorf("wrong loader url: %s", url)
}

func init() {
	c := jsonschema.NewCompiler()
	c.UseLoader(&memLoader{})
	tpSchema = c.MustCompile(tpURL)
}

func bytesToMap(b []byte) (any, error) {
	return jsonschema.UnmarshalJSON(bytes.NewReader(b))
}

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

		m, err := bytesToMap(jsonBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to convert TracingPolicy to map: %w", err)
		}

		if err = tpSchema.Validate(m); err != nil {
			return nil, fmt.Errorf("failed to validate TracingPolicy: %w", err)
		}

		return &gtp, nil
	case v1alpha1.TPNamespacedKindDefinition:
		return nil, fmt.Errorf("namespaced tracing policies not supported in non-k8s builds: %s", kind)
	default:
		return nil, fmt.Errorf("unknown kind: %s", kind)
	}
}
