package main

import (
	"context"
	"testing"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"

	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
)

func TestFuzz(t *testing.T) {
	obs, err := observer.GetDefaultObserver(t, context.TODO(), tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}

	sm := tus.StartTestSensorManager(context.TODO(), t)
	// create and add sensor
	fuzzer := NewKprobeSpecFuzzer()
	kprobeSpec := fuzzer.Generate()
	sensors, err := sensors.SensorsFromPolicy(&tracingpolicy.GenericTracingPolicy{
		ApiVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Metadata: tracingpolicy.Metadata{
			Name: "fuzz",
		},
		Spec: v1alpha1.TracingPolicySpec{
			KProbes: []v1alpha1.KProbeSpec{*kprobeSpec},
		},
	}, 0)
	if err != nil {
		panic(err)
	}

	sm.AddAndEnableSensors(context.TODO(), t, sensors)

	obs.PrintStats()
	

	// sensor, err := createGenericTracepointSensor("GtpLseekTest", []GenericTracepointConf{lseekConf}, policyfilter.NoFilterID, "policyName")
	// if err != nil {
	// 	t.Fatalf("failed to create generic tracepoint sensor: %s", err)
	// }
	// sm.AddAndEnableSensor(ctx, t, sensor, "GtpLseekTest")
}
