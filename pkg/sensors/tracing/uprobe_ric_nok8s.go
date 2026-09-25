// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && nok8s

package tracing

import (
	"errors"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/sensors"
)

var errRICNoK8s = errors.New("resolvePathInContainer needs Kubernetes support, which this build lacks")

func createResolvePathInContainerSensor(*v1alpha1.TracingPolicySpec, *v1alpha1.UProbeSpec, *policyInfo) (*sensors.Sensor, error) {
	return nil, errRICNoK8s
}
