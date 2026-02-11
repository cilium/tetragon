// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package dump

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

type mockFGSClient struct {
	tetragon.FineGuidanceSensorsClient
	getDebugFunc func(ctx context.Context, req *tetragon.GetDebugRequest, opts ...grpc.CallOption) (*tetragon.GetDebugResponse, error)
}

func (m *mockFGSClient) GetDebug(ctx context.Context, req *tetragon.GetDebugRequest, opts ...grpc.CallOption) (*tetragon.GetDebugResponse, error) {
	if m.getDebugFunc != nil {
		return m.getDebugFunc(ctx, req, opts...)
	}
	return nil, errors.New("mock not configured")
}

func TestProcessCache(t *testing.T) {
	t.Run("Success reading process cache", func(t *testing.T) {
		mockClient := &mockFGSClient{
			getDebugFunc: func(_ context.Context, _ *tetragon.GetDebugRequest, _ ...grpc.CallOption) (*tetragon.GetDebugResponse, error) {
				return &tetragon.GetDebugResponse{
					Flag: tetragon.ConfigFlag_CONFIG_FLAG_DUMP_PROCESS_CACHE,
					Arg: &tetragon.GetDebugResponse_Processes{
						Processes: &tetragon.DumpProcessCacheResArgs{
							Processes: []*tetragon.ProcessInternal{
								{Process: &tetragon.Process{Pid: wrapperspb.UInt32(1234)}},
								{Process: &tetragon.Process{Pid: wrapperspb.UInt32(5678)}},
							},
						},
					},
				}, nil
			},
		}

		ctx := context.Background()
		processes, err := GetProcessCacheForDump(ctx, mockClient, 4194304, false, false)

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(processes) != 2 {
			t.Errorf("expected 2 processes, got %d", len(processes))
		}

		if processes[0].Process.Pid.Value != 1234 {
			t.Errorf("expected PID 1234, got %d", processes[0].Process.Pid.Value)
		}
	})

	t.Run("grpc error", func(t *testing.T) {
		mockClient := &mockFGSClient{
			getDebugFunc: func(_ context.Context, _ *tetragon.GetDebugRequest, _ ...grpc.CallOption) (*tetragon.GetDebugResponse, error) {
				return nil, errors.New("connection failed")
			},
		}

		ctx := context.Background()
		_, err := GetProcessCacheForDump(ctx, mockClient, 4194304, false, false)

		if err == nil {
			t.Fatal("expected error, got nil")
		}

		if !strings.Contains(err.Error(), "failed to get process dump debug info") {
			t.Errorf("error %q does not contain 'failed to get process dump debug info'", err.Error())
		}
	})

	t.Run("wrong response flag", func(t *testing.T) {
		mockClient := &mockFGSClient{
			getDebugFunc: func(_ context.Context, _ *tetragon.GetDebugRequest, _ ...grpc.CallOption) (*tetragon.GetDebugResponse, error) {
				return &tetragon.GetDebugResponse{
					Flag: tetragon.ConfigFlag_CONFIG_FLAG_LOG_LEVEL,
				}, nil
			},
		}

		ctx := context.Background()
		_, err := GetProcessCacheForDump(ctx, mockClient, 4194304, false, false)

		if err == nil {
			t.Fatal("expected error, got nil")
		}

		if !strings.Contains(err.Error(), "unexpected response flag") {
			t.Errorf("error %q does not contain 'unexpected response flag'", err.Error())
		}
	})
}
