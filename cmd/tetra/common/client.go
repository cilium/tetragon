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

func connect(ctx context.Context) (*grpc.ClientConn, string, error) {
	connCtx, connCancel := context.WithTimeout(ctx, viper.GetDuration(KeyTimeout))
	defer connCancel()

	var conn *grpc.ClientConn
	var serverAddr string
	var err error

	conn, err = grpc.DialContext(connCtx, viper.GetString(KeyServerAddress), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())

	return conn, serverAddr, err
}

func CliRunErr(fn func(ctx context.Context, cli tetragon.FineGuidanceSensorsClient), fnErr func(err error)) {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	var conn *grpc.ClientConn
	var serverAddr string
	var err error

	backoff := time.Second
	attempts := 0
	for {
		conn, serverAddr, err = connect(ctx)
		if err != nil {
			if attempts < viper.GetInt(KeyRetries) {
				// Exponential backoff
				attempts++
				logger.GetLogger().WithField("server-address", serverAddr).WithField("attempts", attempts).WithError(err).Error("Connection attempt failed, retrying...")
				time.Sleep(backoff)
				backoff *= 2
				continue
			}
			logger.GetLogger().WithField("server-address", serverAddr).WithField("attempts", attempts).WithError(err).Fatal("Failed to connect to server")
			fnErr(err)
		}
		break
	}
	defer conn.Close()

	client := tetragon.NewFineGuidanceSensorsClient(conn)
	fn(ctx, client)
}

func CliRun(fn func(ctx context.Context, cli tetragon.FineGuidanceSensorsClient)) {
	CliRunErr(fn, func(_ error) {})
}
