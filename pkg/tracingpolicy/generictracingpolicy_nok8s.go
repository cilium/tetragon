// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build nok8s

package tracingpolicy

import (
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

// NB: see the corresponding type from the k8s API
type TypeMeta struct {
	Kind       string `json:"kind,omitempty"`
	APIVersion string `json:"apiVersion,omitempty"`
}

// NB: see the corresponding type from the k8s API
type ObjectMeta struct {
	Name        string            `json:"name,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// GenericTracingPolicy represents TracingPolicy CRD.
// It implements TracingPolicy and CRDObject interfaces with pointer receivers.
type GenericTracingPolicy struct {
	TypeMeta
	Metadata ObjectMeta                 `json:"metadata"`
	Spec     v1alpha1.TracingPolicySpec `json:"spec"`
}

func (gtp *GenericTracingPolicy) TpName() string {
	return gtp.Metadata.Name
}

func (gtp *GenericTracingPolicy) TpInfo() string {
	return gtp.Metadata.Name
}

func (gtp *GenericTracingPolicy) TpSpec() *v1alpha1.TracingPolicySpec {
	return &gtp.Spec
}
