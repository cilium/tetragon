// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && nok8s

package tracing

import (
	"errors"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/sensors"
)

// This build has no pod informer, so validation rejects the policy and setup
// is never reached.
func setupResolvePathInContainer(_ *sensors.Sensor, _ *v1alpha1.TracingPolicySpec, _ *policyInfo) {}

func checkResolvePathInContainerSupport() error {
	return errors.New("resolvePathInContainer needs Kubernetes support, which this build lacks")
}
