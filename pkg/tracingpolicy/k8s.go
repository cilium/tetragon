// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build k8s

package tracingpolicy

import (
	"fmt"

	"github.com/cilium/tetragon/pkg/crdutils"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/client"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"
)

var (
	TPContext  *crdutils.CRDContext[*GenericTracingPolicy]
	TPNContext *crdutils.CRDContext[*GenericTracingPolicyNamespaced]
)

func init() {
	var err error
	TPContext, err = crdutils.NewCRDContext[*GenericTracingPolicy](&client.TracingPolicyCRD.Definition)
	if err != nil {
		panic(fmt.Sprintf("failed to initialize CRD context for TracingPolicy: %v", err))
	}
	TPNContext, err = crdutils.NewCRDContext[*GenericTracingPolicyNamespaced](&client.TracingPolicyNamespacedCRD.Definition)
	if err != nil {
		panic(fmt.Sprintf("failed to initialize CRD context for TracingPolicyNamespaced: %v", err))
	}
}

// FromYAML inspects the YAML input to determine the kind, then dispatches to
// the generic FromYAML function.
func FromYAML(data string) (TracingPolicy, error) {
	var unstr unstructured.Unstructured
	if err := yaml.UnmarshalStrict([]byte(data), &unstr); err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML: %w", err)
	}

	switch unstr.GetKind() {
	case v1alpha1.TPKindDefinition:
		obj, err := TPContext.FromYAML(data)
		if err != nil {
			return nil, err
		}
		return obj, nil
	case v1alpha1.TPNamespacedKindDefinition:
		obj, err := TPNContext.FromYAML(data)
		if err != nil {
			return nil, err
		}
		return obj, nil
	default:
		return nil, fmt.Errorf("unknown CRD kind: %s", unstr.GetKind())
	}
}
