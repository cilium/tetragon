// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInpodOptsConf(t *testing.T) {
	opts := inpodOpts{
		grpcAddr:  "10.0.0.1:54321",
		binsDir:   "/bins",
		namespace: "test-ns",
		podLabels: map[string]string{"app": "policytest", "run": "abc123"},
	}

	conf := opts.conf()
	assert.Equal(t, "10.0.0.1:54321", conf.GrpcAddr)
	assert.Equal(t, "/bins", conf.BinsDir)
	assert.Equal(t, "test-ns", conf.Namespace)
	assert.Equal(t, map[string]string{"app": "policytest", "run": "abc123"}, conf.PodSelectorLabels)
	assert.True(t, conf.PodScoped(), "in-pod conf with namespace + labels must be pod-scoped")
}

func TestInpodOptsConf_LocalFallback(t *testing.T) {
	// without a namespace and labels, the conf is not pod-scoped (degenerate
	// local behavior).
	opts := inpodOpts{grpcAddr: "localhost:54321", binsDir: "/bins"}
	conf := opts.conf()
	assert.False(t, conf.PodScoped())
}
