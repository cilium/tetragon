// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package metrics_test

import (
	"slices"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/eventmetrics"
	"github.com/cilium/tetragon/pkg/metricsconfig"
	"github.com/cilium/tetragon/pkg/option"
)

func processExecEvent(binary string) {
	event := tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExec{
			ProcessExec: &tetragon.ProcessExec{
				Process: &tetragon.Process{Binary: binary},
			},
		},
	}
	eventmetrics.ProcessEvent(&tracing.MsgGenericTracepointUnix{PolicyName: "fake-policy"}, &event)
}

// binarySeries calls fn with every series of a metric family and its "binary"
// label value.
func binarySeries(t *testing.T, reg *prometheus.Registry, name string, fn func(binary string, m *dto.Metric)) {
	families, err := reg.Gather()
	require.NoError(t, err)
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, m := range family.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "binary" {
					fn(l.GetValue(), m)
				}
			}
		}
	}
}

// binariesOf returns the sorted "binary" label values of a metric family.
func binariesOf(t *testing.T, reg *prometheus.Registry, name string) []string {
	var out []string
	binarySeries(t, reg, name, func(binary string, _ *dto.Metric) {
		out = append(out, binary)
	})
	slices.Sort(out)
	return out
}

// Eviction deletes series on a separate goroutine.
func requireBinaries(t *testing.T, reg *prometheus.Registry, name string, want []string) {
	t.Helper()
	require.Eventually(t, func() bool {
		return slices.Equal(binariesOf(t, reg, name), want)
	}, 5*time.Second, 10*time.Millisecond, "%s binaries: got %v, want %v", name, binariesOf(t, reg, name), want)
}

func resetProcessMetrics() {
	for _, metric := range metrics.ListMetricsWithPod() {
		metric.Reset()
	}
}

func TestMetricsWithBinaryBounded(t *testing.T) {
	option.Config.MetricsServer = ":0"
	option.Config.EnableEventMetrics = true
	resetProcessMetrics()
	t.Cleanup(func() {
		option.Config.MetricsServer = ""
		option.Config.EnableEventMetrics = false
		require.NoError(t, metrics.InitBinaryCache(0))
		resetProcessMetrics()
	})

	reg := prometheus.NewRegistry()
	metricsconfig.InitEventsMetrics(reg)
	require.NoError(t, metrics.InitBinaryCache(2))

	for _, binary := range []string{"/bin/a", "/bin/b", "/bin/c"} {
		processExecEvent(binary)
	}
	// /bin/a is the least recently seen and must be gone.
	requireBinaries(t, reg, "tetragon_events_total", []string{"/bin/b", "/bin/c"})
	requireBinaries(t, reg, "tetragon_policy_events_total", []string{"/bin/b", "/bin/c"})

	// Seeing /bin/b again keeps it; /bin/c becomes the oldest and is evicted
	// when /bin/a comes back.
	processExecEvent("/bin/b")
	processExecEvent("/bin/a")
	requireBinaries(t, reg, "tetragon_events_total", []string{"/bin/a", "/bin/b"})

	// A size of 0 disables the bound.
	require.NoError(t, metrics.InitBinaryCache(0))
	for _, binary := range []string{"/bin/d", "/bin/e", "/bin/f"} {
		processExecEvent(binary)
	}
	requireBinaries(t, reg, "tetragon_events_total", []string{"/bin/a", "/bin/b", "/bin/d", "/bin/e", "/bin/f"})
}
