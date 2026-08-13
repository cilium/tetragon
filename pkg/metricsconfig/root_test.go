// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metricsconfig

import (
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

// newTestClient returns a client that never reuses connections, so that a
// request made after the server has shut down actually attempts to dial rather
// than picking up a pooled connection.
func newTestClient() *http.Client {
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{DisableKeepAlives: true},
	}
}

// TestEnableMetricsBindError checks that a failure to bind is reported to the
// caller instead of being silently swallowed, which was the bug behind the
// metrics server appearing to start while never serving anything.
func TestEnableMetricsBindError(t *testing.T) {
	t.Run("address already in use", func(t *testing.T) {
		occupied, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() { occupied.Close() })

		stop, err := EnableMetrics(occupied.Addr().String())
		require.Error(t, err)
		require.Nil(t, stop)
	})

	t.Run("malformed address", func(t *testing.T) {
		stop, err := EnableMetrics(":::::2112")
		require.Error(t, err)
		require.Nil(t, stop)
	})
}

// TestMetricsServer covers the happy path and the shutdown path of the metrics
// server. Both subtests share a single server, so they must run sequentially.
func TestMetricsServer(t *testing.T) {
	// Registered on the same package-level registry the server is wired to, so
	// seeing it in the response body proves the handler serves that registry
	// and not, say, an empty one.
	counter := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "tetragon_metricsconfig_test_total",
		Help: "Test-only counter asserting the metrics endpoint serves the registry.",
	})
	GetRegistry().MustRegister(counter)
	t.Cleanup(func() { GetRegistry().Unregister(counter) })
	counter.Inc()

	server, listener, err := newMetricsServer("127.0.0.1:0")
	require.NoError(t, err)

	stop := serve(server, listener)
	t.Cleanup(stop)

	url := "http://" + listener.Addr().String() + "/metrics"
	client := newTestClient()

	t.Run("serves the registry", func(t *testing.T) {
		// No readiness polling needed: the listener is already bound before
		// serve is called, so the kernel queues this connection until Serve()
		// accepts it.
		resp, err := client.Get(url)
		require.NoError(t, err)
		t.Cleanup(func() { resp.Body.Close() })

		require.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Contains(t, string(body), "tetragon_metricsconfig_test_total 1")
	})

	t.Run("shuts down when stop is called", func(t *testing.T) {
		// stop blocks until the serving goroutine has returned, so once it
		// completes the server is guaranteed to no longer answer: no polling
		// needed.
		stop()

		_, err := client.Get(url)
		require.Error(t, err, "metrics server still serving after stop returned")
	})
}
