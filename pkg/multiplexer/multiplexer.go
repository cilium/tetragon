// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package multiplexer

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/logger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"k8s.io/klog/v2"
)

const (
	defaultConnectRetries = 10
	defaultConnectBackoff = time.Second
)

type connResult struct {
	*grpc.ClientConn
	Error error
}

// GetEventsResult encapsulates a GetEventsResponse and an error
type GetEventsResult struct {
	*tetragon.GetEventsResponse
	Error error
}

// ClientMultiplexer multiplexes one or more GetEvents clients into a single stream
type ClientMultiplexer struct {
	clients        []tetragon.FineGuidanceSensorsClient
	connectRetries int
	connectBackoff time.Duration
}

// NewClientMultiplexer constructs a new ClientMultiplexer.
func NewClientMultiplexer() *ClientMultiplexer {
	return &ClientMultiplexer{
		clients:        []tetragon.FineGuidanceSensorsClient{},
		connectRetries: defaultConnectRetries,
		connectBackoff: defaultConnectBackoff,
	}
}

// WithConnectRetries updates the number of attempts this multiplexer will make to connect
// to each gRPC server. The default is 10.
func (cm *ClientMultiplexer) WithConnectRetries(retries uint) *ClientMultiplexer {
	cm.connectRetries = int(retries)
	return cm
}

// WithConnectBackoff updates the backoff time between connection attempts to each gRPC
// server. The default is 1 second.
func (cm *ClientMultiplexer) WithConnectBackoff(backoff time.Duration) *ClientMultiplexer {
	cm.connectBackoff = backoff
	return cm
}

// Connect connects the ClientMultiplexer to one or more gRPC servers specified addrs
func (cm *ClientMultiplexer) Connect(ctx context.Context, connTimeout time.Duration, addrs ...string) error {
	connCtx, connCancel := context.WithTimeout(ctx, connTimeout)
	defer connCancel()

	var wg sync.WaitGroup
	queue := make(chan connResult, len(addrs))
	wg.Add(len(addrs))

	for _, addr := range addrs {
		klog.V(2).InfoS("Connecting to gRPC server...", "addr", addr)
		go func(addr string) {
			defer wg.Done()
			conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				queue <- connResult{nil, fmt.Errorf("%s: %w", addr, err)}
				return
			}
			if !conn.WaitForStateChange(connCtx, conn.GetState()) {
				queue <- connResult{nil, fmt.Errorf("%s: %w", addr, connCtx.Err())}
				return
			}
			queue <- connResult{conn, nil}
			logger.GetLogger().WithField("addr", addr).Info("Connected to gRPC server")
		}(addr)
	}

	// Close the channel when everything is connected
	go func() {
		wg.Wait()
		close(queue)
	}()

	// Pull connections out of the channel
	var conns []*grpc.ClientConn
	var connErrors []error
	for cr := range queue {
		if cr.Error != nil {
			connErrors = append(connErrors, cr.Error)
		} else {
			conns = append(conns, cr.ClientConn)
		}
	}

	// Close everything and abort if we failed to connect to one or more server
	if len(connErrors) > 0 {
		for _, conn := range conns {
			conn.Close()
		}
		return fmt.Errorf("failed to connect to one or more servers: %v", connErrors)
	}

	for _, conn := range conns {
		client := tetragon.NewFineGuidanceSensorsClient(conn)
		cm.clients = append(cm.clients, client)
	}

	return nil
}

// GetEventsWithFilters calls GetEvents for each client in the multiplexer and returns a channel that
// multiplexes the GetEventsResponses. allowList and denyList can be used to filter what
// events we care about.
func (cm *ClientMultiplexer) GetEvents(ctx context.Context, allowList, denyList []*tetragon.Filter) (chan GetEventsResult, error) {
	c := make(chan GetEventsResult)

	for _, client := range cm.clients {
		var stream tetragon.FineGuidanceSensors_GetEventsClient
		var err error
		for i := 0; i < cm.connectRetries; i++ {
			stream, err = client.GetEvents(ctx, &tetragon.GetEventsRequest{
				AllowList: allowList,
				DenyList:  denyList,
			})
			if err == nil {
				break
			}
			time.Sleep(cm.connectBackoff)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to get events after %d tries", cm.connectRetries)
		}
		go func(stream tetragon.FineGuidanceSensors_GetEventsClient) {
			for {
				select {
				case <-ctx.Done():
					logger.GetLogger().Debug("ClientMultiplexer: Context cancelled, stopping GetEvents goroutine")
					return
				default:
				}
				res, err := stream.Recv()
				c <- GetEventsResult{res, err}
			}
		}(stream)
	}

	return c, nil
}
