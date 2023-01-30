// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

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

func (f *FakeObserver) GetSensorConfig(ctx context.Context, k string, v string) (string, error) {
	return "", nil
}

func (f *FakeObserver) SetSensorConfig(ctx context.Context, name string, cfgkey string, cfgval string) error {
	return nil
}

func (f *FakeObserver) GetTreeProto(ctx context.Context, tname string) (*tetragon.StackTraceNode, error) {
	return nil, nil
}

func (f *FakeObserver) AddTracingPolicy(ctx context.Context, tp tracingpolicy.TracingPolicy) error {
	return nil
}

func (f *FakeObserver) DelTracingPolicy(ctx context.Context, sensorName string) error {
	return nil
}

func (f *FakeObserver) RemoveSensor(ctx context.Context, sensorName string) error {
	return nil
}

func (f *FakeObserver) ListTracingPolicies(ctx context.Context) (*tetragon.ListTracingPoliciesResponse, error) {
	return nil, nil
}
