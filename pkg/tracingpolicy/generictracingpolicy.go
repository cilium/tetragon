// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracingpolicy

import (
	"fmt"
	"os"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"

	"github.com/cilium/tetragon/pkg/crdutils"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/client"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
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

// GenericTracingPolicy represents TracingPolicy CRD.
// It implements TracingPolicy and CRDObject interfaces with pointer receivers.
type GenericTracingPolicy struct {
	metav1.TypeMeta
	Metadata metav1.ObjectMeta          `json:"metadata"`
	Spec     v1alpha1.TracingPolicySpec `json:"spec"`
}

func (gtp *GenericTracingPolicy) TpName() string {
	return gtp.Metadata.Name
}

func (gtp *GenericTracingPolicy) TpSpec() *v1alpha1.TracingPolicySpec {
	return &gtp.Spec
}

func (gtp *GenericTracingPolicy) TpInfo() string {
	return gtp.Metadata.Name
}

func (gtp *GenericTracingPolicy) GetObjectMetaStruct() *metav1.ObjectMeta {
	return &gtp.Metadata
}

// GenericTracingPolicyNamespaced represents TracingPolicyNamespaced CRD.
// It implements TracingPolicy and CRDObject interfaces with pointer receivers.
type GenericTracingPolicyNamespaced struct {
	metav1.TypeMeta
	Metadata metav1.ObjectMeta          `json:"metadata"`
	Spec     v1alpha1.TracingPolicySpec `json:"spec"`
}

func (gtp *GenericTracingPolicyNamespaced) TpNamespace() string {
	return gtp.Metadata.Namespace
}

func (gtp *GenericTracingPolicyNamespaced) TpName() string {
	return gtp.Metadata.Name
}

func (gtp *GenericTracingPolicyNamespaced) TpSpec() *v1alpha1.TracingPolicySpec {
	return &gtp.Spec
}

func (gtp *GenericTracingPolicyNamespaced) TpInfo() string {
	return gtp.Metadata.Name
}

func (gtp *GenericTracingPolicyNamespaced) GetObjectMetaStruct() *metav1.ObjectMeta {
	return &gtp.Metadata
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

// FromFile loads a CRD object from a YAML file at the given path.
func FromFile(path string) (TracingPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return FromYAML(string(data))
}
