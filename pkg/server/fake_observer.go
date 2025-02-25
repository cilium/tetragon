// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// nolint:revive // ignore unused parameter alerts, dummy methods
package server

import (
	"context"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

type FakeObserver struct{}

func (f *FakeObserver) AddTracingPolicy(ctx context.Context, tp tracingpolicy.TracingPolicy) error {
	return nil
}

func (f *FakeObserver) DeleteTracingPolicy(ctx context.Context, sensorName string, sensorNamespace string) error {
	return nil
}

func (f *FakeObserver) EnableTracingPolicy(ctx context.Context, sensorName string, sensorNamespace string) error {
	return nil
}

func (f *FakeObserver) DisableTracingPolicy(ctx context.Context, sensorName string, sensorNamespace string) error {
	return nil
}

func (f *FakeObserver) RemoveSensor(ctx context.Context, sensorName string) error {
	return nil
}

func (f *FakeObserver) ListTracingPolicies(ctx context.Context) (*tetragon.ListTracingPoliciesResponse, error) {
	return nil, nil
}

func (h *FakeObserver) ConfigureTracingPolicy(_ context.Context, _ *tetragon.ConfigureTracingPolicyRequest) error {
	return nil
}
