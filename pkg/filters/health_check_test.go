// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package filters

import (
	"context"
	"testing"

	v1 "github.com/cilium/hubble/pkg/api/v1"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/wrapperspb"
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
}

func Test_healthCheckFilter(t *testing.T) {
	maybeHealthCheck, err := BuildFilterList(context.Background(),
		[]*tetragon.Filter{{HealthCheck: &wrapperspb.BoolValue{Value: true}}},
		[]OnBuildFilter{&HealthCheckFilter{}})
	assert.NoError(t, err)
	notHealthCheck, err := BuildFilterList(context.Background(),
		[]*tetragon.Filter{{HealthCheck: &wrapperspb.BoolValue{Value: false}}},
		[]OnBuildFilter{&HealthCheckFilter{}})
	assert.NoError(t, err)

	process := v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{Process: &tetragon.Process{Pod: &tetragon.Pod{Container: &tetragon.Container{
					MaybeExecProbe: true,
				}}}},
			},
		},
	}
	parent := v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{Parent: &tetragon.Process{Pod: &tetragon.Pod{Container: &tetragon.Container{
					MaybeExecProbe: true,
				}}}},
			},
		},
	}
	neither := v1.Event{
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
