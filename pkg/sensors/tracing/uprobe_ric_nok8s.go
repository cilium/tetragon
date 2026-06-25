// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && nok8s

package tracing

import (
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/sensors"
)

// setupResolvePathInContainer is a no-op without Kubernetes support, which
// lacks the pod informer resolvePathInContainer needs.
func setupResolvePathInContainer(*sensors.Sensor, *v1alpha1.TracingPolicySpec, *policyInfo) {}
