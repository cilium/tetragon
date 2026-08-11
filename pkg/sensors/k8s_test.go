// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !nok8s

package sensors

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

func TestValidateNamespacedProbes(t *testing.T) {
	uprobe := v1alpha1.UProbeSpec{
		Path:    "/procRoot/1/root/usr/lib/x86_64-linux-gnu/libc.so.6",
		Symbols: []string{"mount"},
	}
	usdt := v1alpha1.UsdtSpec{Path: "/bin/node", Provider: "test", Name: "usdt0"}

	tests := []struct {
		name      string
		namespace string
		spec      *v1alpha1.TracingPolicySpec
		wantErr   error
	}{
		{
			name:      "cluster-wide uprobe is allowed",
			namespace: "",
			spec:      &v1alpha1.TracingPolicySpec{UProbes: []v1alpha1.UProbeSpec{uprobe}},
			wantErr:   nil,
		},
		{
			name:      "namespaced uprobe is rejected",
			namespace: "tenant",
			spec:      &v1alpha1.TracingPolicySpec{UProbes: []v1alpha1.UProbeSpec{uprobe}},
			wantErr:   errNamespacedUprobe,
		},
		{
			name:      "cluster-wide usdt is allowed",
			namespace: "",
			spec:      &v1alpha1.TracingPolicySpec{Usdts: []v1alpha1.UsdtSpec{usdt}},
			wantErr:   nil,
		},
		{
			name:      "namespaced usdt is rejected",
			namespace: "tenant",
			spec:      &v1alpha1.TracingPolicySpec{Usdts: []v1alpha1.UsdtSpec{usdt}},
			wantErr:   errNamespacedUsdt,
		},
		{
			name:      "namespaced kprobe is unaffected",
			namespace: "tenant",
			spec:      &v1alpha1.TracingPolicySpec{KProbes: []v1alpha1.KProbeSpec{{Call: "sys_open"}}},
			wantErr:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateNamespacedProbes(tt.namespace, tt.spec)
			if tt.wantErr == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, tt.wantErr)
		})
	}
}
