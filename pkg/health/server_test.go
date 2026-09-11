// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package health

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
)

func TestHealthServerProbes(t *testing.T) {
	resetReady()
	t.Cleanup(resetReady)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Start the health server on an ephemeral port.
	addr := StartHealthServer(ctx, "127.0.0.1:0", 1)

	conn, err := grpc.NewClient(addr.String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	client := grpc_health_v1.NewHealthClient(conn)

	// Liveness should always be SERVING.
	liveness, err := client.Check(ctx, &grpc_health_v1.HealthCheckRequest{Service: "liveness"})
	require.NoError(t, err)
	assert.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, liveness.Status)

	// Startup should be NOT_SERVING before SetReady().
	startup, err := client.Check(ctx, &grpc_health_v1.HealthCheckRequest{Service: "startup"})
	require.NoError(t, err)
	assert.Equal(t, grpc_health_v1.HealthCheckResponse_NOT_SERVING, startup.Status)

	SetReady()

	// Liveness should still be SERVING.
	require.Eventually(t, func() bool {
		resp, err := client.Check(ctx, &grpc_health_v1.HealthCheckRequest{Service: "liveness"})
		if err != nil {
			return false
		}
		return resp.Status == grpc_health_v1.HealthCheckResponse_SERVING
	}, 5*time.Second, 100*time.Millisecond)

	// Startup should now be SERVING.
	require.Eventually(t, func() bool {
		resp, err := client.Check(ctx, &grpc_health_v1.HealthCheckRequest{Service: "startup"})
		if err != nil {
			return false
		}
		return resp.Status == grpc_health_v1.HealthCheckResponse_SERVING
	}, 5*time.Second, 100*time.Millisecond)

	// Sanity: GetHealth returns running as well.
	resp, err := GetHealth()
	require.NoError(t, err)
	require.Len(t, resp.GetHealthStatus(), 1)
	assert.Equal(t, "running", resp.GetHealthStatus()[0].Details)
}
