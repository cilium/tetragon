// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import "testing"

func TestConfPodScoped(t *testing.T) {
	tests := []struct {
		name string
		conf Conf
		want bool
	}{
		{
			name: "empty (local case)",
			conf: Conf{},
			want: false,
		},
		{
			name: "namespace only",
			conf: Conf{Namespace: "test-ns"},
			want: false,
		},
		{
			name: "labels only",
			conf: Conf{PodSelectorLabels: map[string]string{"app": "policytest"}},
			want: false,
		},
		{
			name: "namespace and labels (k8s case)",
			conf: Conf{
				Namespace:         "test-ns",
				PodSelectorLabels: map[string]string{"app": "policytest"},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.conf.PodScoped(); got != tt.want {
				t.Errorf("PodScoped() = %v, want %v", got, tt.want)
			}
		})
	}
}
