// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package common

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/logger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func connect(ctx context.Context) (*grpc.ClientConn, string, error) {
	connCtx, connCancel := context.WithTimeout(ctx, Timeout)
	defer connCancel()

	address := ResolveServerAddress()

	conn, err := grpc.DialContext(connCtx, address, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	return conn, address, err
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

type ClientWithContext struct {
	Client tetragon.FineGuidanceSensorsClient
	Ctx    context.Context
	conn   *grpc.ClientConn
	cancel context.CancelFunc
}

// Close cleanup resources, it closes the connection and cancel the context
func (c ClientWithContext) Close() {
	c.conn.Close()
	c.cancel()
}

// NewClientWithDefaultContext return a client to a tetragon server accompanied
// with an initialized context that can be used for the RPC call, caller must
// call Close() on the client.
func NewClientWithDefaultContext() (*ClientWithContext, error) {
	c := &ClientWithContext{}

	var timeout context.Context
	timeout, c.cancel = context.WithTimeout(context.Background(), Timeout)
	// we don't need the cancelFunc here as calling cancel on timeout, the
	// parent, will cancel its children.
	c.Ctx, _ = signal.NotifyContext(timeout, syscall.SIGINT, syscall.SIGTERM)

	address := ResolveServerAddress()

	var err error
	c.conn, err = grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client with address %s: %w", address, err)
	}
	c.Client = tetragon.NewFineGuidanceSensorsClient(c.conn)

	return c, nil
}
