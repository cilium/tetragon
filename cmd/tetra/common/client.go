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

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type daemonInfo struct {
	ServerAddr string `json:"server_address"`
}

func readActiveServerAddress(fname string) (string, error) {
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

func connect(ctx context.Context) (*grpc.ClientConn, string, error) {
	connCtx, connCancel := context.WithTimeout(ctx, Timeout)
	defer connCancel()

	// resolve ServerAdress: if flag set by user, use it, otherwise try to read
	// it from tetragon-info.json, if it doesn't exist, just use default value
	if ServerAddress == "" {
		var err error
		ServerAddress, err = readActiveServerAddress(defaults.InitInfoFile)
		// if address could not be found in tetragon-info.json file, use default
		if err != nil {
			ServerAddress = defaultServerAddress
			logger.GetLogger().WithField("ServerAddress", ServerAddress).Debug("connect to server using default value")
		} else {
			logger.GetLogger().WithFields(logrus.Fields{
				"InitInfoFile":  defaults.InitInfoFile,
				"ServerAddress": ServerAddress,
			}).Debug("connect to server using address in info file")
		}
	}

	conn, err := grpc.NewClient(ServerAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, ServerAddress, err
	}
	if !conn.WaitForStateChange(connCtx, conn.GetState()) {
		return nil, ServerAddress, connCtx.Err()
	}
	return conn, ServerAddress, nil
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
			if attempts < Retries {
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

type ConnectedClient struct {
	Client tetragon.FineGuidanceSensorsClient
	Ctx    context.Context
	conn   *grpc.ClientConn
	cancel context.CancelFunc
}

// Close cleanup resources, it closes the connection and cancel the context
func (c ConnectedClient) Close() {
	c.conn.Close()
	c.cancel()
}

// NewConnectedClient return a connected client to a tetragon server, caller
// must call Close() on the client. On failure to connect, this function calls
// Fatal() thus stopping execution.
func NewConnectedClient() ConnectedClient {
	c := ConnectedClient{}
	c.Ctx, c.cancel = signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	var serverAddr string
	var err error

	backoff := time.Second
	attempts := 0
	for {
		c.conn, serverAddr, err = connect(c.Ctx)
		if err != nil {
			if attempts < Retries {
				// Exponential backoff
				attempts++
				logger.GetLogger().WithField("server-address", serverAddr).WithField("attempts", attempts).WithError(err).Error("Connection attempt failed, retrying...")
				time.Sleep(backoff)
				backoff *= 2
				continue
			}
			logger.GetLogger().WithField("server-address", serverAddr).WithField("attempts", attempts).WithError(err).Fatal("Failed to connect to server")
		}
		break
	}

	c.Client = tetragon.NewFineGuidanceSensorsClient(c.conn)
	return c
}
