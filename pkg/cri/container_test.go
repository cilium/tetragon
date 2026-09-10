// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !nok8s

package cri

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	criapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

var errFakeCRI = errors.New("fake CRI failure")

// The embedded interface satisfies the methods not under test.
type fakeRuntimeClient struct {
	criapi.RuntimeServiceClient
	info      map[string]string
	statusErr error // returned by ContainerStatus when set
}

func (f *fakeRuntimeClient) ContainerStatus(_ context.Context, _ *criapi.ContainerStatusRequest, _ ...grpc.CallOption) (*criapi.ContainerStatusResponse, error) {
	if f.statusErr != nil {
		return nil, f.statusErr
	}
	return &criapi.ContainerStatusResponse{Info: f.info}, nil
}

func TestContainerPID(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cli     *fakeRuntimeClient
		wantPID uint32
		wantErr error
	}{
		{
			name:    "pid from verbose info",
			cli:     &fakeRuntimeClient{info: map[string]string{"info": `{"pid":1234}`}},
			wantPID: 1234,
		},
		{
			name: "info without a pid",
			cli:  &fakeRuntimeClient{info: map[string]string{"info": `{"runtimeSpec":{}}`}},
		},
		{
			name: "no info blob",
			cli:  &fakeRuntimeClient{info: map[string]string{}},
		},
		{
			name:    "RPC failure",
			cli:     &fakeRuntimeClient{statusErr: errFakeCRI},
			wantErr: errFakeCRI,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pid, err := ContainerPID(context.Background(), tc.cli, "abc")
			if tc.wantPID == 0 {
				require.Error(t, err)
				if tc.wantErr != nil {
					require.ErrorIs(t, err, tc.wantErr)
					require.ErrorContains(t, err, "abc", "the container id must reach the caller")
				}
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.wantPID, pid)
		})
	}
}
