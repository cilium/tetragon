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

// gRGC A6 - gRPC Retry Design (a.k.a. built in backoff retry)
// https://github.com/grpc/proposal/blob/master/A6-client-retries.md
// was implemented by https://github.com/grpc/grpc-go/pull/2111 but unusable
// for a long time since maxAttempts was limited to hardcoded 5
// (https://github.com/grpc/grpc-go/issues/4615), recent PR fixed that
// https://github.com/grpc/grpc-go/pull/7229.
//
// It's transparent to the user, to see it in action, make sure the gRPC server
// is unreachable (do not start tetragon for example), run tetra with:
// GRPC_GO_LOG_SEVERITY_LEVEL=warning <tetra cmd>
//
// Note that logs don't always have the time to be pushed before exit so output
// might be a bit off but the number of retries is respected (you can debug or
// synchronously print in the grpc/stream.c:shouldRetry or :withRetry to
// verify).
//
// Also note that the final backoff duration is completely random and chosen
// between 0 and the final duration that was computed via to the params:
// https://github.com/grpc/grpc-go/blob/v1.65.0/stream.go#L702
func RetryPolicy(retries int) string {
	if retries < 0 {
		// gRPC should ignore the invalid retry policy but will issue a warning,
		return "{}"
	}
	// maxAttempt includes the first call
	maxAttempt := retries + 1
	// let's not limit backoff by hardcoding 1h in MaxBackoff
	// since we need to provide a value >0
	return fmt.Sprintf(`{
	"methodConfig": [{
	  "name": [{"service": "tetragon.FineGuidanceSensors"}],
	  "retryPolicy": {
		  "MaxAttempts": %d,
		  "InitialBackoff": "1s",
		  "MaxBackoff": "3600s",
		  "BackoffMultiplier": 2,
		  "RetryableStatusCodes": [ "UNAVAILABLE" ]
	  }
	}]}`, maxAttempt)
}

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
	// Ctx is a combination of the signal context and the timeout context
	Ctx context.Context
	// SignalCtx is only the signal context, you might want to use that context
	// when the command should never timeout (like a stream command)
	SignalCtx context.Context
	conn      *grpc.ClientConn
	// The signal context is the parent of the timeout context, so cancelling
	// signal will cancel its child, timeout
	signalCancel  context.CancelFunc
	timeoutCancel context.CancelFunc
}

// Close cleanup resources, it closes the connection and cancel the context
func (c ClientWithContext) Close() {
	c.conn.Close()
	c.signalCancel()
	c.timeoutCancel() // this should be a nop
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

	c.SignalCtx, c.signalCancel = signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	c.Ctx, c.timeoutCancel = context.WithTimeout(c.SignalCtx, timeout)

	var err error
	c.conn, err = grpc.NewClient(address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultServiceConfig(RetryPolicy(Retries)),
		grpc.WithMaxCallAttempts(Retries+1), // maxAttempt includes the first call
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client with address %s: %w", address, err)
	}
	c.Client = tetragon.NewFineGuidanceSensorsClient(c.conn)

	return c, nil
}
