// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !nok8s

package crdwatcher

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"
)

func TestTracingPolicyAppliesToNode(t *testing.T) {
	node := &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				"node-role.kubernetes.io/worker": "true",
				"kubernetes.io/arch":             "amd64",
				"tetragon.io/canary":             "enabled",
			},
		},
	}

	tests := []struct {
		name         string
		nodeSelector *slimv1.LabelSelector
		want         bool
	}{
		{
			name: "unset selector matches all nodes",
			want: true,
		},
		{
			name:         "empty selector matches all nodes",
			nodeSelector: &slimv1.LabelSelector{},
			want:         true,
		},
		{
			name: "match labels selects node",
			nodeSelector: &slimv1.LabelSelector{
				MatchLabels: map[string]string{"kubernetes.io/arch": "amd64"},
			},
			want: true,
		},
		{
			name: "match labels rejects node",
			nodeSelector: &slimv1.LabelSelector{
				MatchLabels: map[string]string{"kubernetes.io/arch": "arm64"},
			},
			want: false,
		},
		{
			name: "match expressions select node",
			nodeSelector: &slimv1.LabelSelector{
				MatchExpressions: []slimv1.LabelSelectorRequirement{{
					Key:      "tetragon.io/canary",
					Operator: slimv1.LabelSelectorOpIn,
					Values:   []string{"enabled", "shadow"},
				}},
			},
			want: true,
		},
		{
			name: "does not exist expression rejects node",
			nodeSelector: &slimv1.LabelSelector{
				MatchExpressions: []slimv1.LabelSelectorRequirement{{
					Key:      "node-role.kubernetes.io/worker",
					Operator: slimv1.LabelSelectorOpDoesNotExist,
				}},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &v1alpha1.TracingPolicy{
				Spec: v1alpha1.TracingPolicySpec{
					NodeSelector: tt.nodeSelector,
				},
			}

			got, err := tracingPolicyAppliesToNode(policy, node)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestTracingPolicyAppliesToNodeReturnsSelectorError(t *testing.T) {
	policy := &v1alpha1.TracingPolicy{
		Spec: v1alpha1.TracingPolicySpec{
			NodeSelector: &slimv1.LabelSelector{
				MatchExpressions: []slimv1.LabelSelectorRequirement{{
					Key:      "kubernetes.io/arch",
					Operator: "Invalid",
				}},
			},
		},
	}
	node := &corev1.Node{}

	got, err := tracingPolicyAppliesToNode(policy, node)

	require.Error(t, err)
	assert.False(t, got)
}
