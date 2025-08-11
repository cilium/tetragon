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

func TestContainerID(t *testing.T) {
	f := []*tetragon.Filter{{ContainerId: []string{
		"^2f00a73446e0",
	}}}
	fl, err := BuildFilterList(context.Background(), f, []OnBuildFilter{&ContainerIDFilter{}})
	require.NoError(t, err)
	process := tetragon.Process{Docker: "2f00a73446e0"}
	ev := event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{
					Process: &process,
				},
			},
		},
	}
	assert.True(t, fl.MatchOne(&ev))
	process.Docker = "foo"
	assert.False(t, fl.MatchOne(&ev))
}

func TestInInitTree(t *testing.T) {
	f := []*tetragon.Filter{{InInitTree: &wrapperspb.BoolValue{Value: true}}}
	fl, err := BuildFilterList(context.Background(), f, []OnBuildFilter{&InInitTreeFilter{}})
	require.NoError(t, err)
	process := tetragon.Process{}
	ev := event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{
					Process: &process,
				},
			},
		},
	}
	process.InInitTree = &wrapperspb.BoolValue{Value: true}
	assert.True(t, fl.MatchOne(&ev))
	process.InInitTree = &wrapperspb.BoolValue{Value: false}
	assert.False(t, fl.MatchOne(&ev))
	process.InInitTree = nil
	assert.False(t, fl.MatchOne(&ev))

	f = []*tetragon.Filter{{InInitTree: &wrapperspb.BoolValue{Value: false}}}
	fl, err = BuildFilterList(context.Background(), f, []OnBuildFilter{&InInitTreeFilter{}})
	require.NoError(t, err)

	process.InInitTree = &wrapperspb.BoolValue{Value: true}
	assert.False(t, fl.MatchOne(&ev))
	process.InInitTree = &wrapperspb.BoolValue{Value: false}
	assert.True(t, fl.MatchOne(&ev))
	process.InInitTree = nil
	assert.True(t, fl.MatchOne(&ev))
}
