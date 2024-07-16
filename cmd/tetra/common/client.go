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
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func CliRunErr(fn func(ctx context.Context, cli tetragon.FineGuidanceSensorsClient), fnErr func(err error)) {
	c, err := NewClientWithDefaultContextAndAddress()
	if err != nil {
		fnErr(err)
		return
	}
	defer c.Close()
	fn(c.Ctx, c.Client)
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

// NewClientWithDefaultContextAndAddress returns a client to a tetragon
// server after resolving the server address using helpers, accompanied with an
// initialized context that can be used for the RPC call, caller must call
// Close() on the client.
func NewClientWithDefaultContextAndAddress() (*ClientWithContext, error) {
	return NewClient(context.Background(), ResolveServerAddress(), Timeout)
}

func NewClient(ctx context.Context, address string, timeout time.Duration) (*ClientWithContext, error) {
	c := &ClientWithContext{}

	var timeoutContext context.Context
	timeoutContext, c.cancel = context.WithTimeout(ctx, timeout)
	// we don't need the cancelFunc here as calling cancel on timeout, the
	// parent, will cancel its children.
	c.Ctx, _ = signal.NotifyContext(timeoutContext, syscall.SIGINT, syscall.SIGTERM)

	var err error
	c.conn, err = grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client with address %s: %w", address, err)
	}
	c.Client = tetragon.NewFineGuidanceSensorsClient(c.conn)

	return c, nil
}
