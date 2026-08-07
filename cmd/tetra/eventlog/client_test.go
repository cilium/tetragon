// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package eventlog

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/cmd/tetra/common"
)

type retryServer struct {
	tetragon.UnimplementedEventLogServiceServer
	calls atomic.Int32
}

func (s *retryServer) GetEventLogParams(context.Context, *tetragon.GetEventLogParamsRequest) (*tetragon.GetEventLogParamsResponse, error) {
	if s.calls.Add(1) == 1 {
		return nil, status.Error(codes.Unavailable, "try again")
	}
	return &tetragon.GetEventLogParamsResponse{}, nil
}

func TestClientRetriesUnavailableRPC(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	server := grpc.NewServer()
	retrySrv := &retryServer{}
	tetragon.RegisterEventLogServiceServer(server, retrySrv)
	go server.Serve(listener)
	t.Cleanup(func() {
		server.Stop()
		listener.Close()
	})

	oldAddress := common.ServerAddress
	oldRetries := common.Retries
	oldTimeout := common.Timeout
	t.Cleanup(func() {
		common.ServerAddress = oldAddress
		common.Retries = oldRetries
		common.Timeout = oldTimeout
	})
	common.ServerAddress = listener.Addr().String()
	common.Retries = 1
	common.Timeout = 5 * time.Second

	client, err := NewClient()
	require.NoError(t, err)
	t.Cleanup(client.Close)

	_, err = client.Client.GetEventLogParams(client.ctx, &tetragon.GetEventLogParamsRequest{})
	require.NoError(t, err)
	require.Equal(t, int32(2), retrySrv.calls.Load())
}
