// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package filters

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/event"
)

func Test_canBeHealthCheck(t *testing.T) {
	assert.False(t, canBeHealthCheck(nil))
	assert.False(t, canBeHealthCheck(&tetragon.Process{
		Binary:    "myprogram",
		Arguments: "arg-a arg-b argc",
	}))
	assert.False(t, canBeHealthCheck(&tetragon.Process{
		Binary:    "myprogram",
		Arguments: "arg-a arg-b argc",
		Pod:       &tetragon.Pod{},
	}))
	assert.False(t, canBeHealthCheck(&tetragon.Process{
		Binary:    "myprogram",
		Arguments: "arg-a arg-b argc",
		Pod: &tetragon.Pod{
			Container: &tetragon.Container{},
		},
	}))
	assert.True(t, canBeHealthCheck(&tetragon.Process{
		Binary:    "myprogram",
		Arguments: "arg-a arg-b argc",
		Pod: &tetragon.Pod{
			Container: &tetragon.Container{
				MaybeExecProbe: true,
			},
		},
	}))

}

func Test_maybeExecProbe(t *testing.T) {
	assert.False(t, MaybeExecProbe("/usr/bin/myprogram", "arg-a arg-b arg-c", []string{"myprogram", "arg-a", "arg-b"}))
	assert.True(t, MaybeExecProbe("/usr/bin/myprogram", "arg-a arg-b arg-c", []string{"myprogram", "arg-a", "arg-b", "arg-c"}))
	assert.True(t, MaybeExecProbe(
		"/bin/ash",
		"-c \"! curl -s --fail --connect-timeout 5 -o /dev/null echo-a/private\"",
		[]string{"ash", "-c", "! curl -s --fail --connect-timeout 5 -o /dev/null echo-a/private"}))
	assert.True(t, MaybeExecProbe("/bin/grpc_health_probe", "-addr=:5050", []string{"/bin/grpc_health_probe", "-addr=:5050"}))
	assert.False(t, MaybeExecProbe("/some/other/path/to/grpc_health_probe", "-addr=:5050", []string{"/bin/grpc_health_probe", "-addr=:5050"}))
	assert.True(t, MaybeExecProbe("/bin/grpc_health_probe", "-addr=:5050", []string{"grpc_health_probe", "-addr=:5050"}))
	assert.False(t, MaybeExecProbe("/bin/grpc_health_probe", "-addr=:5050", []string{}))
	assert.True(t, MaybeExecProbe("/bin/bash_health_probe.sh", "/bin/bash_health_probe.sh test arguments", []string{"/bin/bash_health_probe.sh", "test", "arguments"}))
	assert.False(t, MaybeExecProbe("/bin/bash_health_probe_no_ext", "/bin/bash_health_probe_no_ext test arguments", []string{"/bin/bash_health_probe", "test", "arguments"}))
}

func Test_healthCheckFilter(t *testing.T) {
	maybeHealthCheck, err := BuildFilterList(context.Background(),
		[]*tetragon.Filter{{HealthCheck: &wrapperspb.BoolValue{Value: true}}},
		[]OnBuildFilter{&HealthCheckFilter{}})
	require.NoError(t, err)
	notHealthCheck, err := BuildFilterList(context.Background(),
		[]*tetragon.Filter{{HealthCheck: &wrapperspb.BoolValue{Value: false}}},
		[]OnBuildFilter{&HealthCheckFilter{}})
	require.NoError(t, err)

	process := event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{Process: &tetragon.Process{Pod: &tetragon.Pod{Container: &tetragon.Container{
					MaybeExecProbe: true,
				}}}},
			},
		},
	}
	parent := event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{Parent: &tetragon.Process{Pod: &tetragon.Pod{Container: &tetragon.Container{
					MaybeExecProbe: true,
				}}}},
			},
		},
	}
	neither := event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{Process: &tetragon.Process{Pod: &tetragon.Pod{Container: &tetragon.Container{}}}},
			},
		},
	}

	assert.True(t, maybeHealthCheck.MatchOne(&process))
	assert.True(t, maybeHealthCheck.MatchOne(&parent))
	assert.False(t, maybeHealthCheck.MatchOne(&neither))
	assert.False(t, notHealthCheck.MatchOne(&process))
	assert.False(t, notHealthCheck.MatchOne(&parent))
	assert.True(t, notHealthCheck.MatchOne(&neither))
}
