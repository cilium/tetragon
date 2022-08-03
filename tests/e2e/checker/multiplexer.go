// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package checker

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"k8s.io/klog/v2"
)

const (
	connectRetries = 10
	connectBackoff = time.Second
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
	clients []tetragon.FineGuidanceSensorsClient
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

			conn, err := grpc.DialContext(
				connCtx,
				addr,
				grpc.WithTransportCredentials(insecure.NewCredentials()),
				// grpc.WithKeepaliveParams(keepalive.ClientParameters{
				// 	Time:                connTimeout / 2,
				// 	Timeout:             connTimeout,
				// 	PermitWithoutStream: true,
				// }),
			)

			if err != nil {
				queue <- connResult{nil, fmt.Errorf("%s: %w", addr, err)}
				return
			}

			queue <- connResult{conn, nil}
			klog.InfoS("Connected to gRPC server", "addr", addr)
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
		for i := 0; i < connectRetries; i++ {
			stream, err = client.GetEvents(ctx, &tetragon.GetEventsRequest{
				AllowList: allowList,
				DenyList:  denyList,
			})
			if err == nil {
				break
			}
			time.Sleep(connectBackoff)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to get events after %d tries", connectRetries)
		}
		go func(stream tetragon.FineGuidanceSensors_GetEventsClient) {
			for {
				select {
				case <-ctx.Done():
					klog.V(2).Info("ClientMultiplexer: Context cancelled, stopping GetEvents goroutine")
					return
				default:
				}
				klog.V(4).Info("ClientMultiplexer: Calling stream.Recv()")
				res, err := stream.Recv()
				klog.V(4).Info("ClientMultiplexer: Queueing a response")
				c <- GetEventsResult{res, err}
			}
		}(stream)
	}

	return c, nil
}
