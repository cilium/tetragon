// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && nok8s

package tracing

import (
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/sensors"
)

// setupResolvePathInContainer is a no-op without Kubernetes support, which
// lacks the pod informer resolvePathInContainer needs. Warn so a policy that
// loads but traces nothing is diagnosable.
func setupResolvePathInContainer(_ *sensors.Sensor, spec *v1alpha1.TracingPolicySpec, _ *policyInfo) {
	if !hasResolvePathInContainer(spec) {
		return
	}
	logger.GetLogger().Warn("uprobe resolvePathInContainer needs Kubernetes support, " +
		"which this build lacks: no container uprobes will be attached")
}
