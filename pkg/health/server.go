// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package health

import (
	"context"
	"net"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"google.golang.org/grpc"
	gh "google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
)

var (
	log = logger.GetLogger()
)

func StartHealthServer(ctx context.Context, address string, interval int) {
	// Create a new health server and mark it as serving.
	healthServer := gh.NewServer()
	healthServer.SetServingStatus("liveness", grpc_health_v1.HealthCheckResponse_SERVING)

	// Create a new gRPC server for health checks and register the healthServer.
	grpcHealthServer := grpc.NewServer()
	grpc_health_v1.RegisterHealthServer(grpcHealthServer, healthServer)

	// Start the gRPC server for the health checks.
	go func() {
		// the gRPC server for the health checks listens on port 6789
		listener, err := net.Listen("tcp", address)
		if err != nil {
			logger.Fatal(log, "Failed to listen for gRPC healthserver")
		}

		log.Info("Starting gRPC health server", "address", address, "interval", interval)
		if err = grpcHealthServer.Serve(listener); err != nil {
			logger.Fatal(log, "Failed to start gRPC healthserver", logfields.Error, err)
		}
	}()

	// Check the agent health periodically. To check if our agent is health we call
	// health.GetHealth() and we report the status to the healthServer.
	go func() {
		ticker := time.NewTicker(time.Duration(interval) * time.Second)
		for {
			select {
			case <-ticker.C:
				servingStatus := grpc_health_v1.HealthCheckResponse_NOT_SERVING
				if response, err := GetHealth(); err == nil {
					if st := response.GetHealthStatus(); len(st) > 0 && st[0].Status == tetragon.HealthStatusResult_HEALTH_STATUS_RUNNING {
						servingStatus = grpc_health_v1.HealthCheckResponse_SERVING
					}
				}
				healthServer.SetServingStatus("liveness", servingStatus)
			case <-ctx.Done():
				ticker.Stop()
				healthServer.Shutdown() // set all services to NOT_SERVING
				grpcHealthServer.Stop()
				return
			}
		}
	}()
}
