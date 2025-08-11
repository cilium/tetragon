// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package policymetrics

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/tetragon/pkg/observer"
	tuo "github.com/cilium/tetragon/pkg/testutils/observer"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

func Test_policyStatusCollector_Collect(t *testing.T) {
	expectedMetrics := func(disabled, enabled, err, load_error int) io.Reader {
		return strings.NewReader(fmt.Sprintf(`# HELP tetragon_tracingpolicy_kernel_memory_bytes The amount of kernel memory in bytes used by policy's sensors non-shared BPF maps (memlock).
# TYPE tetragon_tracingpolicy_kernel_memory_bytes gauge
tetragon_tracingpolicy_kernel_memory_bytes{policy="pizza", policy_namespace=""} 0
tetragon_tracingpolicy_kernel_memory_bytes{policy="amazing-one", policy_namespace=""} 0
tetragon_tracingpolicy_kernel_memory_bytes{policy="amazing-one", policy_namespace="default"} 0
tetragon_tracingpolicy_kernel_memory_bytes{policy="amazing-one", policy_namespace="kube-system"} 0
# HELP tetragon_tracingpolicy_loaded The number of loaded tracing policy by state.
# TYPE tetragon_tracingpolicy_loaded gauge
tetragon_tracingpolicy_loaded{state="disabled"} %d
tetragon_tracingpolicy_loaded{state="enabled"} %d
tetragon_tracingpolicy_loaded{state="error"} %d
tetragon_tracingpolicy_loaded{state="load_error"} %d
`, disabled, enabled, err, load_error))
	}

	reg := prometheus.NewRegistry()

	// NB(kkourt): the policy state collector uses observer.GetSensorManager() to get the sensor
	// manager because in the observer tests we only initialize metrics while the observer
	// changes for every test (see:
	// https://github.com/cilium/tetragon/blob/22eb995b19207ac0ced2dd83950ec8e8aedd122d/pkg/observer/observertesthelper/observer_test_helper.go#L272-L276)
	manager := tuo.GetTestSensorManagerWithDummyPF(t).Manager
	observer.SetSensorManager(manager)
	t.Cleanup(observer.ResetSensorManager)

	collector := NewPolicyCollector()
	reg.Register(collector)

	err := manager.AddTracingPolicy(context.TODO(), &tracingpolicy.GenericTracingPolicy{
		Metadata: v1.ObjectMeta{
			Name: "pizza",
		},
	})
	require.NoError(t, err)
	// Add three policies with the same name: one clusterwide, two namespaced
	err = manager.AddTracingPolicy(context.TODO(), &tracingpolicy.GenericTracingPolicy{
		Metadata: v1.ObjectMeta{
			Name: "amazing-one",
		},
	})
	require.NoError(t, err)
	err = manager.AddTracingPolicy(context.TODO(), &tracingpolicy.GenericTracingPolicyNamespaced{
		Metadata: v1.ObjectMeta{
			Name:      "amazing-one",
			Namespace: "default",
		},
	})
	require.NoError(t, err)
	err = manager.AddTracingPolicy(context.TODO(), &tracingpolicy.GenericTracingPolicyNamespaced{
		Metadata: v1.ObjectMeta{
			Name:      "amazing-one",
			Namespace: "kube-system",
		},
	})
	require.NoError(t, err)
	err = testutil.CollectAndCompare(collector, expectedMetrics(0, 4, 0, 0))
	require.NoError(t, err)

	err = manager.DisableTracingPolicy(context.TODO(), "pizza", "")
	require.NoError(t, err)
	err = testutil.CollectAndCompare(collector, expectedMetrics(1, 3, 0, 0))
	require.NoError(t, err)
}
