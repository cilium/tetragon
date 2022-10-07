// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package common

import (
	"context"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func CliRunErr(fn func(ctx context.Context, cli tetragon.FineGuidanceSensorsClient), fnErr func(err error)) {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	connCtx, connCancel := context.WithTimeout(ctx, 10*time.Second)
	defer connCancel()
	conn, err := grpc.DialContext(connCtx, viper.GetString(KeyServerAddress), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		fnErr(err)
		logger.GetLogger().WithError(err).Fatal("Failed to connect")
	}
	defer conn.Close()
	client := tetragon.NewFineGuidanceSensorsClient(conn)
	fn(ctx, client)
}

func CliRun(fn func(ctx context.Context, cli tetragon.FineGuidanceSensorsClient)) {
	CliRunErr(fn, func(_ error) {})
}
