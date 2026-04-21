// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !nok8s

package crdwatcher

import (
	"encoding/json"

	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

type Tp[T any] interface {
	TpSpec() *v1alpha1.TracingPolicySpec
	DeepCopy() T
	GetAnnotations() map[string]string
}

func restoreNullSelectors[T Tp[T]](tp T) T {
	ret := tp.DeepCopy()
	restoreNullSelectorsFromLastApplied(ret.GetAnnotations(), ret.TpSpec())
	return ret
}

// restoreNullSelectorsFromLastApplied recovers explicit null selectors from the
// kubectl last-applied annotation. This is needed because client-side
// `kubectl apply` removes the distinction between explicit null and omitted
// fields for CRD defaults before the object reaches Tetragon.
func restoreNullSelectorsFromLastApplied(annotations map[string]string, spec *v1alpha1.TracingPolicySpec) {
	lastApplied, ok := annotations[corev1.LastAppliedConfigAnnotation]
	if !ok {
		return
	}

	var obj map[string]any
	if err := json.Unmarshal([]byte(lastApplied), &obj); err != nil {
		return
	}

	specMap, ok := obj["spec"].(map[string]any)
	if !ok {
		return
	}

	if val, ok := specMap["hostSelector"]; ok && val == nil {
		spec.HostSelector = nil
	}

	if val, ok := specMap["podSelector"]; ok && val == nil {
		spec.PodSelector = nil
	}

	if val, ok := specMap["containerSelector"]; ok && val == nil {
		spec.ContainerSelector = nil
	}
}
