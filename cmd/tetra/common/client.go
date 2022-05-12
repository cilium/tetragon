// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package common

import (
	"context"
	"os/signal"
	"time"

	"github.com/cilium/tetragon/api/v1/fgs"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/spf13/viper"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func CliRunErr(fn func(ctx context.Context, cli fgs.FineGuidanceSensorsClient), fnErr func(err error)) {
	ctx, cancel := signal.NotifyContext(context.Background(), unix.SIGINT, unix.SIGTERM)
	defer cancel()

	connCtx, connCancel := context.WithTimeout(ctx, 10*time.Second)
	defer connCancel()
	conn, err := grpc.DialContext(connCtx, viper.GetString(KeyServerAddress), grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		fnErr(err)
		logger.GetLogger().WithError(err).Fatal("Failed to connect")
	}
	defer conn.Close()
	client := fgs.NewFineGuidanceSensorsClient(conn)
	fn(ctx, client)
}

func CliRun(fn func(ctx context.Context, cli fgs.FineGuidanceSensorsClient)) {
	CliRunErr(fn, func(_ error) {})
}
