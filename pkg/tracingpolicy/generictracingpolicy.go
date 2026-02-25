// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracingpolicy

import (
	"os"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

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

// FromFile loads a CRD object from a YAML file at the given path.
func FromFile(path string) (TracingPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return FromYAML(string(data))
}
