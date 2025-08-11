// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package filters

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/event"
)

func TestLabelSelectorFilterInvalidFilter(t *testing.T) {
	filter := []*tetragon.Filter{{Labels: []string{"!@#$%"}}}
	_, err := BuildFilterList(context.Background(), filter, []OnBuildFilter{&LabelsFilter{}})
	require.Error(t, err)
}

func TestLabelSelectorFilterInvalidEvent(t *testing.T) {
	filter := []*tetragon.Filter{{Labels: []string{"key1,key2"}}}
	fl, err := BuildFilterList(context.Background(), filter, []OnBuildFilter{&LabelsFilter{}})
	require.NoError(t, err)

	// nil pod should not match.
	exec := tetragon.GetEventsResponse_ProcessExec{
		ProcessExec: &tetragon.ProcessExec{Process: &tetragon.Process{}},
	}
	ev := event.Event{Event: &tetragon.GetEventsResponse{Event: &exec}}
	assert.False(t, fl.MatchOne(&ev))

	// nil process should not match.
	exec.ProcessExec.Process = nil
	assert.False(t, fl.MatchOne(&ev))
}

func TestLabelSelectorFilterNoValue(t *testing.T) {
	filter := []*tetragon.Filter{{Labels: []string{"key1,key2"}}}
	fl, err := BuildFilterList(context.Background(), filter, []OnBuildFilter{&LabelsFilter{}})
	require.NoError(t, err)
	exec := tetragon.GetEventsResponse_ProcessExec{
		ProcessExec: &tetragon.ProcessExec{Process: &tetragon.Process{Pod: &tetragon.Pod{PodLabels: map[string]string{}}}},
	}
	ev := event.Event{Event: &tetragon.GetEventsResponse{Event: &exec}}
	assert.False(t, fl.MatchOne(&ev))
	exec.ProcessExec.Process.Pod.PodLabels = map[string]string{"key3": "val3"}
	assert.False(t, fl.MatchOne(&ev))
	exec.ProcessExec.Process.Pod.PodLabels = map[string]string{"key1": "val1"}
	assert.False(t, fl.MatchOne(&ev))
	exec.ProcessExec.Process.Pod.PodLabels = map[string]string{"key1": "val1", "key2": "val2"}
	assert.True(t, fl.MatchOne(&ev))
	exec.ProcessExec.Process.Pod.PodLabels = map[string]string{"key1": "val1", "key2": "val2", "key3": "val3"}
	assert.True(t, fl.MatchOne(&ev))
}

func TestLabelSelectorFilterWithValue(t *testing.T) {
	filter := []*tetragon.Filter{{Labels: []string{"key1=val1,key2=val2"}}}
	fl, err := BuildFilterList(context.Background(), filter, []OnBuildFilter{&LabelsFilter{}})
	require.NoError(t, err)
	exec := tetragon.GetEventsResponse_ProcessExec{
		ProcessExec: &tetragon.ProcessExec{Process: &tetragon.Process{Pod: &tetragon.Pod{PodLabels: map[string]string{}}}},
	}
	ev := event.Event{Event: &tetragon.GetEventsResponse{Event: &exec}}
	assert.False(t, fl.MatchOne(&ev))
	exec.ProcessExec.Process.Pod.PodLabels = map[string]string{"key3": "val3"}
	assert.False(t, fl.MatchOne(&ev))
	exec.ProcessExec.Process.Pod.PodLabels = map[string]string{"key1": "val1"}
	assert.False(t, fl.MatchOne(&ev))
	exec.ProcessExec.Process.Pod.PodLabels = map[string]string{"key1": "foo", "key2": "bar"}
	assert.False(t, fl.MatchOne(&ev))
	exec.ProcessExec.Process.Pod.PodLabels = map[string]string{"key1": "val1", "key2": "val2"}
	assert.True(t, fl.MatchOne(&ev))
	exec.ProcessExec.Process.Pod.PodLabels = map[string]string{"key1": "val1", "key2": "val2", "key3": "val3"}
	assert.True(t, fl.MatchOne(&ev))
}

func TestLabelSelectorFilterEmptySelector(t *testing.T) {
	filter := []*tetragon.Filter{{Labels: []string{""}}}
	fl, err := BuildFilterList(context.Background(), filter, []OnBuildFilter{&LabelsFilter{}})
	require.NoError(t, err)
	exec := tetragon.GetEventsResponse_ProcessExec{
		ProcessExec: &tetragon.ProcessExec{Process: &tetragon.Process{Pod: &tetragon.Pod{PodLabels: map[string]string{}}}},
	}

	// empty selector matches everything.
	ev := event.Event{Event: &tetragon.GetEventsResponse{Event: &exec}}
	assert.True(t, fl.MatchOne(&ev))
	exec.ProcessExec.Process.Pod.PodLabels = map[string]string{"key3": "val3"}
	assert.True(t, fl.MatchOne(&ev))
	exec.ProcessExec.Process.Pod.PodLabels = map[string]string{"key1": "val1"}
	assert.True(t, fl.MatchOne(&ev))
	exec.ProcessExec.Process.Pod.PodLabels = map[string]string{"key1": "foo", "key2": "bar"}
	assert.True(t, fl.MatchOne(&ev))
	exec.ProcessExec.Process.Pod.PodLabels = map[string]string{"key1": "val1", "key2": "val2"}
	assert.True(t, fl.MatchOne(&ev))
	exec.ProcessExec.Process.Pod.PodLabels = map[string]string{"key1": "val1", "key2": "val2", "key3": "val3"}
	assert.True(t, fl.MatchOne(&ev))
}

func TestLabelSelectorFilterSetSelector(t *testing.T) {
	filter := []*tetragon.Filter{{Labels: []string{"key1 in (foo, bar), key2 notin (baz)"}}}
	fl, err := BuildFilterList(context.Background(), filter, []OnBuildFilter{&LabelsFilter{}})
	require.NoError(t, err)
	exec := tetragon.GetEventsResponse_ProcessExec{
		ProcessExec: &tetragon.ProcessExec{Process: &tetragon.Process{Pod: &tetragon.Pod{PodLabels: map[string]string{}}}},
	}

	ev := event.Event{Event: &tetragon.GetEventsResponse{Event: &exec}}
	assert.False(t, fl.MatchOne(&ev))
	exec.ProcessExec.Process.Pod.PodLabels = map[string]string{"key1": "foo"}
	assert.True(t, fl.MatchOne(&ev))
	exec.ProcessExec.Process.Pod.PodLabels = map[string]string{"key1": "bar", "key2": "baz"}
	assert.False(t, fl.MatchOne(&ev))
	exec.ProcessExec.Process.Pod.PodLabels = map[string]string{"key1": "foo", "key2": "foo"}
	assert.True(t, fl.MatchOne(&ev))
	exec.ProcessExec.Process.Pod.PodLabels = map[string]string{"key1": "foo", "key2": "foo", "key3": "foo"}
	assert.True(t, fl.MatchOne(&ev))
}
