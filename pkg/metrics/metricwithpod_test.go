// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metrics_test

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/eventmetrics"
	"github.com/cilium/tetragon/pkg/metricsconfig"
)

var sampleMsgGenericTracepointUnix = tracing.MsgGenericTracepointUnix{
	PolicyName: "fake-policy",
}

func TestPodDelete(t *testing.T) {
	reg := metricsconfig.GetRegistry()
	metricsconfig.InitAllMetrics(reg)

	// Process four events, each one with different combination of pod/namespace.
	// These events should be counted by multiple metrics with a "pod" label:
	// * tetragon_events_total
	// * tetragon_policy_events_total
	// * tetragon_syscalls_total
	for _, namespace := range []string{"fake-namespace", "other-namespace"} {
		for _, pod := range []string{"fake-pod", "other-pod"} {
			event := tetragon.GetEventsResponse{
				Event: &tetragon.GetEventsResponse_ProcessTracepoint{
					ProcessTracepoint: &tetragon.ProcessTracepoint{
						Subsys: "raw_syscalls",
						Event:  "sys_enter",
						Process: &tetragon.Process{
							Pod: &tetragon.Pod{
								Namespace: namespace,
								Name:      pod,
							},
						},
						Args: []*tetragon.KprobeArgument{
							{
								Arg: &tetragon.KprobeArgument_SyscallId{
									SyscallId: &tetragon.SyscallId{Id: 0, Abi: "x64"},
								},
							},
						},
					},
				},
			}
			eventmetrics.ProcessEvent(&sampleMsgGenericTracepointUnix, &event)
		}
	}
	checkMetricSeriesCount(t, reg, 4)

	// Exactly one timeseries should be deleted for each metric (matching both
	// pod name and namespace).
	metrics.DeleteMetricsForPod(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "fake-pod",
			Namespace: "fake-namespace",
		},
	})
	checkMetricSeriesCount(t, reg, 3)
}

func checkMetricSeriesCount(t *testing.T, registry *prometheus.Registry, seriesCount int) {
	metricFamilies, err := registry.Gather()
	require.NoError(t, err)

	metricNameToSeries := map[string]*io_prometheus_client.MetricFamily{}
	for _, metricFamily := range metricFamilies {
		metricNameToSeries[*metricFamily.Name] = metricFamily
	}
	for _, metric := range []string{"tetragon_events_total", "tetragon_policy_events_total", "tetragon_syscalls_total"} {
		metricFamily := metricNameToSeries[metric]
		require.NotNil(t, metricFamily)
		assert.Len(t, metricFamily.Metric, seriesCount)
	}
}
