// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !nok8s

package cri

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	criapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

var errNotFound = errors.New("not found")

type fakeRuntimeClient struct {
	criapi.RuntimeServiceClient
	containerInfo map[string]string
	sandboxInfo   map[string]string
}

func (f *fakeRuntimeClient) ContainerStatus(context.Context, *criapi.ContainerStatusRequest, ...grpc.CallOption) (*criapi.ContainerStatusResponse, error) {
	if f.containerInfo == nil {
		return nil, errNotFound
	}
	return &criapi.ContainerStatusResponse{Info: f.containerInfo}, nil
}

func (f *fakeRuntimeClient) PodSandboxStatus(context.Context, *criapi.PodSandboxStatusRequest, ...grpc.CallOption) (*criapi.PodSandboxStatusResponse, error) {
	if f.sandboxInfo == nil {
		return nil, errNotFound
	}
	return &criapi.PodSandboxStatusResponse{Info: f.sandboxInfo}, nil
}

func TestCgroupPath(t *testing.T) {
	tests := []struct {
		name    string
		cli     *fakeRuntimeClient
		want    string
		wantErr bool
	}{
		{
			name: "container cgroupfs path",
			cli: &fakeRuntimeClient{containerInfo: map[string]string{
				"info": `{"pid":1,"runtimeSpec":{"linux":{"cgroupsPath":"/kubepods/besteffort/pod1/abc"}}}`,
			}},
			want: "/kubepods/besteffort/pod1/abc",
		},
		{
			name: "container systemd path",
			cli: &fakeRuntimeClient{containerInfo: map[string]string{
				"info": `{"runtimeSpec":{"linux":{"cgroupsPath":"kubepods-besteffort.slice:cri-containerd:abc"}}}`,
			}},
			want: filepath.Join("/kubepods.slice", "kubepods-besteffort.slice", "cri-containerd-abc.scope"),
		},
		{
			name: "pod sandbox fallback",
			cli: &fakeRuntimeClient{sandboxInfo: map[string]string{
				"info": `{"runtimeSpec":{"linux":{"cgroupsPath":"/kubepods/pod1/sandbox"}}}`,
			}},
			want: "/kubepods/pod1/sandbox",
		},
		{
			name:    "neither container nor sandbox",
			cli:     &fakeRuntimeClient{},
			wantErr: true,
		},
		{
			name:    "no info key",
			cli:     &fakeRuntimeClient{containerInfo: map[string]string{"other": "{}"}},
			wantErr: true,
		},
		{
			name: "missing cgroupsPath",
			cli: &fakeRuntimeClient{containerInfo: map[string]string{
				"info": `{"runtimeSpec":{"linux":{}}}`,
			}},
			wantErr: true,
		},
		{
			name:    "malformed json",
			cli:     &fakeRuntimeClient{containerInfo: map[string]string{"info": `{"runtimeSpec":`}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CgroupPath(t.Context(), tt.cli, "abc")
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestContainerPid(t *testing.T) {
	tests := []struct {
		name    string
		info    map[string]string
		want    uint32
		wantErr bool
	}{
		{name: "running", info: map[string]string{"info": `{"pid":4242}`}, want: 4242},
		{name: "not running", info: map[string]string{"info": `{"pid":0}`}, wantErr: true},
		{name: "no info key", info: map[string]string{"other": "{}"}, wantErr: true},
		{name: "malformed json", info: map[string]string{"info": `{"pid":`}, wantErr: true},
		{name: "unknown container", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ContainerPid(t.Context(), &fakeRuntimeClient{containerInfo: tt.info}, "abc")
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
