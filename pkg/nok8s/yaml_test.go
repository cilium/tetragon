// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package nok8s

import (
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseK8sObjErrors(t *testing.T) {
	tests := []struct {
		name string
		yaml string
	}{
		{"empty string", ""},
		{"no kind field", "apiVersion: v1\nmetadata:\n  name: test"},
		{"empty kind", "kind: \"\"\napiVersion: v1"},
		{"invalid yaml", "invalid: yaml: ["},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := ParseK8sObj(tt.yaml)
			assert.Error(t, err)
		})
	}
}

func TestParseK8sObjJSONContent(t *testing.T) {
	yaml := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: test-policy
  labels:
    app: pizza
spec:
  enabled: true
  items:
    - name: first
    - name: second
`
	kind, jsonBytes, err := ParseK8sObj(yaml)
	require.NoError(t, err)
	assert.Equal(t, "TracingPolicy", kind)

	var got map[string]any
	require.NoError(t, json.Unmarshal(jsonBytes, &got))

	want := map[string]any{
		"apiVersion": "cilium.io/v1alpha1",
		"kind":       "TracingPolicy",
		"metadata": map[string]any{
			"name": "test-policy",
			"labels": map[string]any{
				"app": "pizza",
			},
		},
		"spec": map[string]any{
			"enabled": true,
			"items": []any{
				map[string]any{"name": "first"},
				map[string]any{"name": "second"},
			},
		},
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("parsed JSON mismatch:\n%s", diff)
	}
}
