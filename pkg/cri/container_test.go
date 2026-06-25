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

// errFakeCRI is a sentinel returned by the fake runtime client to exercise
// error paths.
var errFakeCRI = errors.New("fake CRI failure")

// fakeRuntimeClient implements only the methods under test; the embedded
// interface satisfies the rest (and panics if any other method is called).
type fakeRuntimeClient struct {
	criapi.RuntimeServiceClient
	info       map[string]string
	containers []*criapi.Container
	sandboxes  []*criapi.PodSandbox
	statusErr  error // returned by ContainerStatus when set
	listConErr error // returned by ListContainers when set
	listSbErr  error // returned by ListPodSandbox when set
}

func (f *fakeRuntimeClient) ContainerStatus(_ context.Context, _ *criapi.ContainerStatusRequest, _ ...grpc.CallOption) (*criapi.ContainerStatusResponse, error) {
	if f.statusErr != nil {
		return nil, f.statusErr
	}
	return &criapi.ContainerStatusResponse{Info: f.info}, nil
}

// ListContainers honors the state filter (as the real runtime does) so the test
// exercises the CONTAINER_RUNNING filter rather than assuming it.
func (f *fakeRuntimeClient) ListContainers(_ context.Context, req *criapi.ListContainersRequest, _ ...grpc.CallOption) (*criapi.ListContainersResponse, error) {
	if f.listConErr != nil {
		return nil, f.listConErr
	}
	if st := req.GetFilter().GetState(); st != nil {
		var items []*criapi.Container
		for _, c := range f.containers {
			if c.GetState() == st.GetState() {
				items = append(items, c)
			}
		}
		return &criapi.ListContainersResponse{Containers: items}, nil
	}
	return &criapi.ListContainersResponse{Containers: f.containers}, nil
}

// ListPodSandbox honors the state filter so the test exercises the
// SANDBOX_READY filter.
func (f *fakeRuntimeClient) ListPodSandbox(_ context.Context, req *criapi.ListPodSandboxRequest, _ ...grpc.CallOption) (*criapi.ListPodSandboxResponse, error) {
	if f.listSbErr != nil {
		return nil, f.listSbErr
	}
	if st := req.GetFilter().GetState(); st != nil {
		var items []*criapi.PodSandbox
		for _, sb := range f.sandboxes {
			if sb.GetState() == st.GetState() {
				items = append(items, sb)
			}
		}
		return &criapi.ListPodSandboxResponse{Items: items}, nil
	}
	return &criapi.ListPodSandboxResponse{Items: f.sandboxes}, nil
}

func TestContainerPID(t *testing.T) {
	// pid present in verbose info -> returned.
	cli := &fakeRuntimeClient{info: map[string]string{
		"info": `{"pid":1234,"runtimeSpec":{"root":{"path":"rootfs"}}}`,
	}}
	pid, err := ContainerPID(context.Background(), cli, "abc")
	require.NoError(t, err)
	require.Equal(t, uint32(1234), pid)

	// no pid in info -> error.
	noPid := &fakeRuntimeClient{info: map[string]string{"info": `{"runtimeSpec":{}}`}}
	_, err = ContainerPID(context.Background(), noPid, "abc")
	require.Error(t, err)

	// no info blob -> error.
	noInfo := &fakeRuntimeClient{info: map[string]string{}}
	_, err = ContainerPID(context.Background(), noInfo, "abc")
	require.Error(t, err)

	// RPC error -> wrapped error mentioning the container id.
	rpcErr := &fakeRuntimeClient{statusErr: errFakeCRI}
	_, err = ContainerPID(context.Background(), rpcErr, "abc")
	require.ErrorIs(t, err, errFakeCRI)
}

func TestRunningContainers(t *testing.T) {
	running := &criapi.ContainerStateValue{State: criapi.ContainerState_CONTAINER_RUNNING}
	cli := &fakeRuntimeClient{
		sandboxes: []*criapi.PodSandbox{
			{
				Id:       "sb1",
				State:    criapi.PodSandboxState_SANDBOX_READY,
				Metadata: &criapi.PodSandboxMetadata{Uid: "uid-1", Namespace: "ns1", Name: "pod1"},
				Labels:   map[string]string{"app": "sshd"},
			},
			{
				// not-ready sandbox: filtered out, so its containers are skipped.
				Id:       "sb2",
				State:    criapi.PodSandboxState_SANDBOX_NOTREADY,
				Metadata: &criapi.PodSandboxMetadata{Uid: "uid-2", Namespace: "ns2", Name: "pod2"},
				Labels:   map[string]string{"app": "nginx"},
			},
		},
		containers: []*criapi.Container{
			{Id: "c1", PodSandboxId: "sb1", State: running.State},
			{Id: "c2", PodSandboxId: "sb1", State: running.State},
			// unknown sandbox -> skipped (no pod metadata).
			{Id: "c3", PodSandboxId: "missing", State: running.State},
			// running container in a not-ready sandbox -> skipped.
			{Id: "c4", PodSandboxId: "sb2", State: running.State},
			// non-running container -> filtered out by the state filter.
			{Id: "c5", PodSandboxId: "sb1", State: criapi.ContainerState_CONTAINER_EXITED},
		},
	}

	got, err := RunningContainers(context.Background(), cli)
	require.NoError(t, err)
	require.ElementsMatch(t, []RunningContainer{
		{ID: "c1", PodUID: "uid-1", Namespace: "ns1", PodLabels: map[string]string{"app": "sshd"}},
		{ID: "c2", PodUID: "uid-1", Namespace: "ns1", PodLabels: map[string]string{"app": "sshd"}},
	}, got)

	// ListPodSandbox failure -> error.
	_, err = RunningContainers(context.Background(), &fakeRuntimeClient{listSbErr: errFakeCRI})
	require.ErrorIs(t, err, errFakeCRI)

	// ListContainers failure -> error.
	_, err = RunningContainers(context.Background(), &fakeRuntimeClient{listConErr: errFakeCRI})
	require.ErrorIs(t, err, errFakeCRI)
}
