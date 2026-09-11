// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package health

import (
	"context"
	"net"
	"time"

	"google.golang.org/grpc"
	gh "google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
)

var (
	log = logger.GetLogger()
)

// StartHealthServer starts the gRPC health server on the given address. It
// returns the address the server is actually listening on, which is useful
// when the caller passes ":0" to bind to an ephemeral port.
func StartHealthServer(ctx context.Context, address string, interval int) net.Addr {
	// Create a new health server and mark it as serving.
	healthServer := gh.NewServer()
	healthServer.SetServingStatus("liveness", grpc_health_v1.HealthCheckResponse_SERVING)
	healthServer.SetServingStatus("startup", grpc_health_v1.HealthCheckResponse_NOT_SERVING)

	// Create a new gRPC server for health checks and register the healthServer.
	grpcHealthServer := grpc.NewServer()
	grpc_health_v1.RegisterHealthServer(grpcHealthServer, healthServer)

	// Start the gRPC server for the health checks.
	listener, err := net.Listen("tcp", address)
	if err != nil {
		logger.Fatal(log, "Failed to listen for gRPC healthserver")
	}

	go func() {
		log.Info("Starting gRPC health server", "address", listener.Addr().String(), "interval", interval)
		if err = grpcHealthServer.Serve(listener); err != nil {
			logger.Fatal(log, "Failed to start gRPC healthserver", logfields.Error, err)
		}
	}()

	// Check the agent health periodically. Liveness only cares that the main
	// process is running and the health server is responding, so keep it
	// always SERVING. The startup service follows GetHealth() and tells the
	// kubelet when the agent has finished initializing without risking a
	// restart during the init window.
	go func() {
		ticker := time.NewTicker(time.Duration(interval) * time.Second)
		for {
			select {
			case <-ticker.C:
				// Keep liveness pinned to SERVING so that a long initialization
				// window does not cause the kubelet to restart the container.
				healthServer.SetServingStatus("liveness", grpc_health_v1.HealthCheckResponse_SERVING)

				startupStatus := grpc_health_v1.HealthCheckResponse_NOT_SERVING
				if response, err := GetHealth(); err == nil {
					if st := response.GetHealthStatus(); len(st) > 0 && st[0].Status == tetragon.HealthStatusResult_HEALTH_STATUS_RUNNING {
						startupStatus = grpc_health_v1.HealthCheckResponse_SERVING
					}
				}
				healthServer.SetServingStatus("startup", startupStatus)
			case <-ctx.Done():
				ticker.Stop()
				healthServer.Shutdown() // set all services to NOT_SERVING
				grpcHealthServer.Stop()
				return
			}
		}
	}()

	return listener.Addr()
}
