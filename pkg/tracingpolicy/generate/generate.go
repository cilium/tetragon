// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package generate

import (
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func NewTracingPolicy(name string) *v1alpha1.TracingPolicy {
	ret := v1alpha1.TracingPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind: "TracingPolicy",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			// CreationTimestamp is not a pointer so it will not be omitted, so let's
			// just at a timestamp.
			// https://github.com/kubernetes/kubernetes/issues/67610
			CreationTimestamp: v1.Now(),
		},
	}

	return &ret
}

func AddKprobe(tp *v1alpha1.TracingPolicy) *v1alpha1.KProbeSpec {
	idx := len(tp.Spec.KProbes)
	tp.Spec.KProbes = append(tp.Spec.KProbes, v1alpha1.KProbeSpec{})
	return &tp.Spec.KProbes[idx]
}
