// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// nolint:revive // ignore unused parameter alerts, dummy methods
package server

import (
	"context"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

type FakeObserver struct{}

func (f *FakeObserver) ListSensors(ctx context.Context) (*[]sensors.SensorStatus, error) {
	return nil, nil
}

func (f *FakeObserver) EnableSensor(ctx context.Context, name string) error {
	return nil
}

func (f *FakeObserver) DisableSensor(ctx context.Context, name string) error {
	return nil
}

func (f *FakeObserver) GetTreeProto(ctx context.Context, tname string) (*tetragon.StackTraceNode, error) {
	return nil, nil
}

func (f *FakeObserver) AddTracingPolicy(ctx context.Context, tp tracingpolicy.TracingPolicy) error {
	return nil
}

func (f *FakeObserver) DeleteTracingPolicy(ctx context.Context, sensorName string) error {
	return nil
}

func (f *FakeObserver) EnableTracingPolicy(ctx context.Context, sensorName string) error {
	return nil
}

func (f *FakeObserver) DisableTracingPolicy(ctx context.Context, sensorName string) error {
	return nil
}

func (f *FakeObserver) RemoveSensor(ctx context.Context, sensorName string) error {
	return nil
}

func (f *FakeObserver) ListTracingPolicies(ctx context.Context) (*tetragon.ListTracingPoliciesResponse, error) {
	return nil, nil
}
