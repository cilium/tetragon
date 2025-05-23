// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package filters

import (
	"context"
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/event"
	"github.com/stretchr/testify/assert"
)

func TestArgumentsRegexFilterBasic(t *testing.T) {
	f := []*tetragon.Filter{{ArgumentsRegex: []string{
		"^-namespace moby -id \\w+ -address /run/containerd/containerd.sock$",
		"^-H fd:// --containerd=/run/containerd/containerd.sock$",
		"^--log /run/containerd/io.containerd.runtime.v2.task/moby/\\w+/log.json --log-format json$",
	}}}
	fl, err := BuildFilterList(context.Background(), f, []OnBuildFilter{&ArgumentsRegexFilter{}})
	assert.NoError(t, err)
	process := tetragon.Process{Arguments: "-namespace moby -id 1234abcd -address /run/containerd/containerd.sock"}
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
	process.Arguments = "-H fd:// --containerd=/run/containerd/containerd.sock"
	assert.True(t, fl.MatchOne(&ev))
	process.Arguments = "--log /run/containerd/io.containerd.runtime.v2.task/moby/abcd1234/log.json --log-format json"
	assert.True(t, fl.MatchOne(&ev))
	process.Arguments = "--no-match"
	assert.False(t, fl.MatchOne(&ev))
}

func TestParentArgumentsRegexFilter(t *testing.T) {
	f := []*tetragon.Filter{{ParentArgumentsRegex: []string{
		"^foo$",
		"^--bar \\d+$",
	}}}
	fl, err := BuildFilterList(context.Background(), f, []OnBuildFilter{&ParentArgumentsRegexFilter{}})
	assert.NoError(t, err)
	process := tetragon.Process{Arguments: "foo"}
	ev := event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{
					Parent: &process,
				},
			},
		},
	}
	assert.True(t, fl.MatchOne(&ev))
	process.Arguments = "--bar 12"
	assert.True(t, fl.MatchOne(&ev))
	process.Arguments = "--no-match"
	assert.False(t, fl.MatchOne(&ev))
}

func TestArgumentsRegexFilterInvalidRegex(t *testing.T) {
	f := []*tetragon.Filter{{ArgumentsRegex: []string{"*"}}}
	_, err := BuildFilterList(context.Background(), f, []OnBuildFilter{&ArgumentsRegexFilter{}})
	assert.Error(t, err)
}

func TestArgumentsRegexFilterInvalidEvent(t *testing.T) {
	f := []*tetragon.Filter{{ArgumentsRegex: []string{".*"}}}
	fl, err := BuildFilterList(context.Background(), f, []OnBuildFilter{&ArgumentsRegexFilter{}})
	assert.NoError(t, err)
	assert.False(t, fl.MatchOne(nil))
	assert.False(t, fl.MatchOne(&event.Event{Event: nil}))
	assert.False(t, fl.MatchOne(&event.Event{Event: struct{}{}}))
	assert.False(t, fl.MatchOne(&event.Event{Event: &tetragon.GetEventsResponse{Event: nil}}))
	assert.False(t, fl.MatchOne(&event.Event{Event: &tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExec{ProcessExec: &tetragon.ProcessExec{Process: nil}},
	}}))
	assert.False(t, fl.MatchOne(&event.Event{Event: &tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExec{ProcessExec: &tetragon.ProcessExec{Process: nil}},
	}}))
	assert.False(t, fl.MatchOne(&event.Event{Event: &tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExec{ProcessExec: &tetragon.ProcessExec{Process: nil}},
	}}))
}
