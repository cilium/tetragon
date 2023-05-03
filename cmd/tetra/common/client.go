// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package common

import (
	"context"
	"encoding/json"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type daemonInfo struct {
	ServerAddr string `json:"server_address"`
}

func getActiveServAddr(fname string) (string, error) {
	f, err := os.Open(fname)
	if err != nil {
		return "", err
	}
	defer f.Close()

	var info daemonInfo
	if err := json.NewDecoder(f).Decode(&info); err != nil {
		return "", err
	}

	return info.ServerAddr, nil
}

func CliRunErr(fn func(ctx context.Context, cli tetragon.FineGuidanceSensorsClient), fnErr func(err error)) {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	connCtx, connCancel := context.WithTimeout(ctx, 10*time.Second)
	defer connCancel()

	var conn *grpc.ClientConn
	var serverAddr string
	var err error

	// The client cli can run remotely so to support most cases transparently
	// Check if the server address was set
	//   - If yes: use it directly, users know better
	//   - If no: then try the default tetragon-info.json file to find the best
	//       address if possible (could be unix socket). This also covers the
	//       case that default address is localhost so we are operating in localhost
	//       context anyway.
	//       If that address is set try it, if it fails for any reason then retry
	//       last time with the server address.
	if viper.IsSet(KeyServerAddress) == false {
		// server-address was not set by user, try the tetragon-info.json file
		serverAddr, err = getActiveServAddr(defaults.InitInfoFile)
		if err == nil && serverAddr != "" {
			conn, err = grpc.DialContext(connCtx, serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
		}
		// Handle both errors
		if err != nil {
			logger.GetLogger().WithFields(logrus.Fields{
				"InitInfoFile":   defaults.InitInfoFile,
				"server-address": serverAddr,
			}).WithError(err).Debugf("Failed to connect to server")
		}
	}
	if conn == nil {
		// Try the server-address prameter
		serverAddr = viper.GetString(KeyServerAddress)
		conn, err = grpc.DialContext(connCtx, serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	}
	if err != nil {
		fnErr(err)
		logger.GetLogger().WithField("server-address", serverAddr).WithError(err).Fatal("Failed to connect to server")
	}
	defer conn.Close()
	client := tetragon.NewFineGuidanceSensorsClient(conn)
	fn(ctx, client)
}

func CliRun(fn func(ctx context.Context, cli tetragon.FineGuidanceSensorsClient)) {
	CliRunErr(fn, func(_ error) {})
}
