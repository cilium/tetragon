// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !nok8s

package tracingpolicy

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

type TypeMeta = metav1.TypeMeta
type ObjectMeta = metav1.ObjectMeta

// GenericTracingPolicy represents TracingPolicy CRD.
// It implements TracingPolicy and CRDObject interfaces with pointer receivers.
type GenericTracingPolicy struct {
	TypeMeta
	Metadata ObjectMeta                 `json:"metadata"`
	Spec     v1alpha1.TracingPolicySpec `json:"spec"`
}

func (gtp *GenericTracingPolicy) TpNamespace() string {
	return gtp.Metadata.Namespace
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
