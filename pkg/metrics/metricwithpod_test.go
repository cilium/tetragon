// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !nok8s && !windows

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

func TestMetricsWithPod(t *testing.T) {
	eventMetrics := []string{"tetragon_events_total", "tetragon_policy_events_total", "tetragon_syscalls_total"}
	healthMetrics := []string{"tetragon_build_info", "tetragon_data_events_total"}

	reg := metricsconfig.GetRegistry()

	// Only health metrics should be present
	// * tetragon_build_info
	// * tetragon_data_events_total
	t.Run("TestPodDeleteHealthMetricsOnly", func(t *testing.T) {
		metricsconfig.InitHealthMetrics(reg)

		deletePod()
		metricSeries := getMetricSeries(t, reg)

		for _, metric := range healthMetrics {
			require.NotNil(t, metricSeries[metric])
		}

		// Event metrics should be nil, even though the pod was deleted
		for _, metric := range eventMetrics {
			require.Nil(t, metricSeries[metric])
		}

	})

	// Process four events, each one with different combination of pod/namespace.
	// These events should be counted by multiple metrics with a "pod" label:
	// * tetragon_events_total
	// * tetragon_policy_events_total
	// * tetragon_syscalls_total
	t.Run("TestPodDeleteHealthAndEventMetrics", func(t *testing.T) {
		metricsconfig.InitEventsMetrics(reg)

		deletePod()
		metricSeries := getMetricSeries(t, reg)
		checkMetricSeriesCount(t, metricSeries, eventMetrics, 4)

		// Exactly one timeseries should be deleted for each metric (matching both
		// pod name and namespace).
		metrics.DeleteMetricsForPod(&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "fake-pod",
				Namespace: "fake-namespace",
			},
		})

		metricSeries = getMetricSeries(t, reg)
		checkMetricSeriesCount(t, metricSeries, eventMetrics, 3)
	})
}

func deletePod() {
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
}

func getMetricSeries(t *testing.T, registry *prometheus.Registry) map[string]*io_prometheus_client.MetricFamily {
	metricFamilies, err := registry.Gather()
	require.NoError(t, err)

	metricNameToSeries := map[string]*io_prometheus_client.MetricFamily{}
	for _, metricFamily := range metricFamilies {
		metricNameToSeries[*metricFamily.Name] = metricFamily
	}
	return metricNameToSeries
}

func checkMetricSeriesCount(t *testing.T, metricSeries map[string]*io_prometheus_client.MetricFamily, metrics []string, seriesCount int) {
	for _, metric := range metrics {
		metricFamily := metricSeries[metric]
		require.NotNil(t, metricFamily)
		assert.Len(t, metricFamily.Metric, seriesCount)
	}
}
