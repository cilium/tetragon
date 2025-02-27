// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/idtable"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func Fuzz_parseString(f *testing.F) {
	f.Fuzz(func(_ *testing.T, input []byte) {
		reader := bytes.NewReader(input)
		parseString(reader)
	})
}

func Test_parseString(t *testing.T) {
	tests := []struct {
		name    string
		input   bytes.Reader
		want    string
		wantErr bool
	}{
		{"normal", *bytes.NewReader([]byte{6, 0, 0, 0, 'p', 'i', 'z', 'z', 'a', 0}), "pizza", false},
		{"shortened", *bytes.NewReader([]byte{3, 0, 0, 0, 'p', 'i', 'z', 'z', 'a', 0}), "piz", false},
		{"too large", *bytes.NewReader([]byte{0, 0, 0, 1, 'p', 'i', 'z', 'z', 'a', 0}), "", true},
		{"error code -2", *bytes.NewReader([]byte{254, 255, 255, 255, 'p', 'i', 'z', 'z', 'a', 0}), "", true},
		{"negative size", *bytes.NewReader([]byte{253, 255, 255, 255, 'p', 'i', 'z', 'z', 'a', 0}), "", true},
		{"missing content", *bytes.NewReader([]byte{1, 0, 0, 0}), "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseString(&tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("got error = %s, wantErr %t", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
	t.Run("remove trailing null byte", func(t *testing.T) {
		out, err := parseString(bytes.NewReader([]byte{6, 0, 0, 0, 'p', 'i', 'z', 'z', 'a', 0}))
		if err != nil {
			t.Errorf("unexpected error %v", err)
		}
		if out != "pizza" {
			t.Errorf("got %q, want %q", out, "pizza")
		}
	})
}

func Test_SensorDestroyHook(t *testing.T) {
	if genericKprobeTable.Len() != 0 {
		t.Errorf("genericKprobeTable expected initial length: 0, got: %d", genericKprobeTable.Len())
	}

	spec := &v1alpha1.TracingPolicySpec{}

	spec.KProbes = []v1alpha1.KProbeSpec{
		{
			Call:    "test_symbol",
			Syscall: false,
		},
	}

	// we use createGenericKprobeSensor because it's where the DestroyHook is
	// created. It would be technically more correct if it was added just after
	// insertion in the table in AddKprobe, but this is done by the caller to
	// have just DestroyHook that regroups all the potential multiple kprobes
	// contained in one sensor.
	policyInfo, err := newPolicyInfoFromSpec("", "test_policy", policyfilter.NoFilterID, spec, nil)
	require.NoError(t, err)
	sensor, err := createGenericKprobeSensor(spec, "test_sensor", policyInfo)
	if err != nil {
		t.Errorf("createGenericKprobeSensor err expected: nil, got: %s", err)
	}

	if genericKprobeTable.Len() != 1 {
		t.Errorf("genericKprobeTable expected length: 1, got: %d", genericKprobeTable.Len())
	}

	// the return sensor entry does not expose anything publicly so we cannot
	// check anything more than the length of the table, hopefully GetEntry on a
	// non-existing ID will return an error
	_, err = genericKprobeTable.GetEntry(idtable.EntryID{ID: 0})
	if err != nil {
		t.Errorf("genericKprobeTable.GetEntry err expected: nil, got: %s", err)
	}

	// For testing purposes, we simulate that the sensor was loaded, because
	// otherwise, Unload will immediately exit when seeing that this sensor was
	// never loaded
	sensor.Loaded = true

	// Destroy should call the DestroyHook that was set in
	// createGenericKprobeSensor and do the cleanup
	sensor.Destroy(true)

	// Table implem detail: the entry still technically exists in the table but
	// is invalid, thus is not taken into account in the length
	if genericKprobeTable.Len() != 0 {
		t.Errorf("genericKprobeTable expected length after cleanup: 0, got: %d", genericKprobeTable.Len())
	}
}

const (
	tcpConnectPolicyName      = "test"
	tcpConnectPolicyNamespace = ""
)

var tcpConnectPolicy = v1alpha1.TracingPolicy{
	ObjectMeta: v1.ObjectMeta{
		Name: tcpConnectPolicyName,
	},
	Spec: v1alpha1.TracingPolicySpec{
		KProbes: []v1alpha1.KProbeSpec{
			{
				Call:    "tcp_connect",
				Syscall: false,
			},
		},
	},
}

// Test_DisableEnablePolicy_Kprobe tests that disabling and enabling a tracing
// policy containing a kprobe works. This is following a regression:
// https://github.com/cilium/tetragon/issues/1489
func Test_DisableEnablePolicy_Kprobe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tus.LoadInitialSensor(t)
	path := bpf.MapPrefixPath()
	mgr, err := sensors.StartSensorManager(path)
	assert.NoError(t, err)

	t.Run("sensor", func(t *testing.T) {
		err = mgr.AddTracingPolicy(ctx, &tcpConnectPolicy)
		assert.NoError(t, err)
		t.Cleanup(func() {
			err = mgr.DeleteTracingPolicy(ctx, tcpConnectPolicyName, tcpConnectPolicyNamespace)
			assert.NoError(t, err)
		})

		err = mgr.DisableSensor(ctx, tcpConnectPolicyName)
		assert.NoError(t, err)
		err = mgr.EnableSensor(ctx, tcpConnectPolicyName)
		assert.NoError(t, err)
	})

	t.Run("tracing-policy", func(t *testing.T) {
		err = mgr.AddTracingPolicy(ctx, &tcpConnectPolicy)
		assert.NoError(t, err)
		t.Cleanup(func() {
			err = mgr.DeleteTracingPolicy(ctx, tcpConnectPolicyName, tcpConnectPolicyNamespace)
			assert.NoError(t, err)
		})

		err = mgr.DisableTracingPolicy(ctx, tcpConnectPolicyName, tcpConnectPolicyNamespace)
		assert.NoError(t, err)
		err = mgr.EnableTracingPolicy(ctx, tcpConnectPolicyName, tcpConnectPolicyNamespace)
		assert.NoError(t, err)
	})
}

// Test_DisableEnablePolicy_KernelMemoryBytes first check that disabling and
// enabling a policy works and then verifies that the kernel memory bytes for a
// loaded policy is non-zero, and that for a disabled policy it's zero.
func Test_DisableEnablePolicy_KernelMemoryBytes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tus.LoadInitialSensor(t)
	path := bpf.MapPrefixPath()
	mgr, err := sensors.StartSensorManager(path)
	require.NoError(t, err)

	err = mgr.AddTracingPolicy(ctx, &tcpConnectPolicy)
	require.NoError(t, err)
	t.Cleanup(func() {
		err = mgr.DeleteTracingPolicy(ctx, tcpConnectPolicyName, tcpConnectPolicyNamespace)
		assert.NoError(t, err)
	})

	list, err := mgr.ListTracingPolicies(ctx)
	require.NoError(t, err)
	require.Len(t, list.Policies, 1)
	assert.Equal(t, tetragon.TracingPolicyState_TP_STATE_ENABLED, list.Policies[0].State)
	assert.NotZero(t, list.Policies[0].KernelMemoryBytes)

	err = mgr.DisableTracingPolicy(ctx, tcpConnectPolicyName, tcpConnectPolicyNamespace)
	require.NoError(t, err)

	list, err = mgr.ListTracingPolicies(ctx)
	require.NoError(t, err)
	require.Len(t, list.Policies, 1)
	assert.Equal(t, tetragon.TracingPolicyState_TP_STATE_DISABLED, list.Policies[0].State)
	assert.Zero(t, list.Policies[0].KernelMemoryBytes)

	err = mgr.EnableTracingPolicy(ctx, tcpConnectPolicyName, tcpConnectPolicyNamespace)
	require.NoError(t, err)

	list, err = mgr.ListTracingPolicies(ctx)
	require.NoError(t, err)
	require.Len(t, list.Policies, 1)
	assert.Equal(t, tetragon.TracingPolicyState_TP_STATE_ENABLED, list.Policies[0].State)
	assert.NotZero(t, list.Policies[0].KernelMemoryBytes)
}
