// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package grpc

import (
	"context"
	"encoding/base64"
	"os"
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/grpc/exec"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/cilium"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/cilium/tetragon/pkg/watcher"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestProcessManager_getPodInfo(t *testing.T) {
	podA := corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Name:      "pod-a",
			Namespace: "namespace-a",
		},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name:        "pod-a-container-a-name",
					Image:       "pod-a-image-a-name",
					ImageID:     "pod-a-image-a-id",
					ContainerID: "docker://aaaaaaaaaaaaaaa",
					State: corev1.ContainerState{
						Running: &corev1.ContainerStateRunning{
							StartedAt: v1.Time{
								Time: time.Unix(1, 2),
							},
						},
					},
				},
			},
		},
	}

	_, err := cilium.InitCiliumState(context.Background(), false)
	assert.NoError(t, err)
	pods := []interface{}{&podA}
	err = process.InitCache(context.Background(), watcher.NewFakeK8sWatcher(pods), false, 10)
	assert.NoError(t, err)
	defer process.FreeCache()
	pod, endpoint := process.GetPodInfo("container-id-not-found", "", "", 0)
	assert.Nil(t, pod)
	assert.Nil(t, endpoint)
	pod, endpoint = process.GetPodInfo("aaaaaaa", "", "", 1234)
	assert.Equal(t,
		&tetragon.Pod{
			Namespace: podA.Namespace,
			Name:      podA.Name,
			Container: &tetragon.Container{
				Id:   podA.Status.ContainerStatuses[0].ContainerID,
				Name: podA.Status.ContainerStatuses[0].Name,
				Image: &tetragon.Image{
					Id:   podA.Status.ContainerStatuses[0].ImageID,
					Name: podA.Status.ContainerStatuses[0].Image,
				},
				StartTime: &timestamppb.Timestamp{
					Seconds: int64(podA.Status.ContainerStatuses[0].State.Running.StartedAt.Second()),
					Nanos:   int32(podA.Status.ContainerStatuses[0].State.Running.StartedAt.Nanosecond()),
				},
				Pid: &wrapperspb.UInt32Value{Value: 1234},
			},
		}, pod)
	assert.Nil(t, endpoint)
}

func TestProcessManager_getPodInfoMaybeExecProbe(t *testing.T) {
	var podA = corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Name:      "pod-a",
			Namespace: "namespace-a",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "pod-a-container-a-name",
					LivenessProbe: &corev1.Probe{
						Handler: corev1.Handler{
							Exec: &corev1.ExecAction{
								Command: []string{"command", "arg-a", "arg-b"},
							},
						},
					},
				},
			},
		},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{
					Name:        "pod-a-container-a-name",
					ContainerID: "docker://aaaaaaaaaaaaaaa",
				},
			},
		},
	}
	pods := []interface{}{&podA}
	err := process.InitCache(context.Background(), watcher.NewFakeK8sWatcher(pods), false, 10)
	assert.NoError(t, err)
	defer process.FreeCache()
	pod, endpoint := process.GetPodInfo("aaaaaaa", "/bin/command", "arg-a arg-b", 1234)
	assert.Equal(t,
		&tetragon.Pod{
			Namespace: podA.Namespace,
			Name:      podA.Name,
			Container: &tetragon.Container{
				Id:             podA.Status.ContainerStatuses[0].ContainerID,
				Name:           podA.Status.ContainerStatuses[0].Name,
				Image:          &tetragon.Image{},
				Pid:            &wrapperspb.UInt32Value{Value: 1234},
				MaybeExecProbe: true,
			},
		}, pod)
	assert.Nil(t, endpoint)
}

func TestProcessManager_GetProcessExec(t *testing.T) {
	err := process.InitCache(context.Background(), watcher.NewFakeK8sWatcher(nil), false, 10)
	assert.NoError(t, err)
	defer process.FreeCache()
	pm, err := NewProcessManager(
		cilium.GetFakeCiliumState(),
		nil,
		false, false, false, false)
	assert.NoError(t, err)
	procInternal := process.AddExecEvent(&processapi.MsgExecveEventUnix{
		Common: processapi.MsgCommon{
			Ktime: 1234,
		},
		Capabilities: processapi.MsgCapabilities{
			Permitted:   1,
			Effective:   1,
			Inheritable: 1,
		},
		Process: processapi.MsgProcess{
			PID: 5678,
		},
	})

	execGrpc := exec.New(pm.execCache, pm.eventCache, pm.enableProcessCred, pm.enableProcessNs)
	assert.Nil(t, execGrpc.GetProcessExec(procInternal).Process.Cap)

	// cap field should be set with enable-process-cred flag.
	pm.enableProcessCred = true
	execGrpc = exec.New(pm.execCache, pm.eventCache, pm.enableProcessCred, pm.enableProcessNs)
	assert.Equal(t,
		&tetragon.Capabilities{
			Permitted:   []tetragon.CapabilitiesType{tetragon.CapabilitiesType_CAP_CHOWN},
			Effective:   []tetragon.CapabilitiesType{tetragon.CapabilitiesType_CAP_CHOWN},
			Inheritable: []tetragon.CapabilitiesType{tetragon.CapabilitiesType_CAP_CHOWN},
		},
		execGrpc.GetProcessExec(procInternal).Process.Cap)
}

func Test_getNodeNameForExport(t *testing.T) {
	assert.Equal(t, "", node.GetNodeNameForExport())
	assert.NoError(t, os.Setenv("NODE_NAME", "from-node-name"))
	assert.Equal(t, "from-node-name", node.GetNodeNameForExport())
	assert.NoError(t, os.Setenv("HUBBLE_NODE_NAME", "from-hubble-node-name"))
	assert.Equal(t, "from-hubble-node-name", node.GetNodeNameForExport())
	assert.NoError(t, os.Unsetenv("NODE_NAME"))
	assert.NoError(t, os.Unsetenv("HUBBLE_NODE_NAME"))
}

func TestProcessManager_GetProcessID(t *testing.T) {
	assert.NoError(t, os.Setenv("NODE_NAME", "my-node"))

	err := process.InitCache(context.Background(), watcher.NewFakeK8sWatcher([]interface{}{}), false, 10)
	assert.NoError(t, err)
	defer process.FreeCache()
	id := process.GetProcessID(1, 2)
	decoded, err := base64.StdEncoding.DecodeString(id)
	assert.NoError(t, err)
	assert.Equal(t, "my-node:2:1", string(decoded))
	assert.NoError(t, os.Unsetenv("NODE_NAME"))
}
