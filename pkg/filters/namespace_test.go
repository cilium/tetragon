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

func TestNamespace(t *testing.T) {
	f := []*tetragon.Filter{{Namespace: []string{"kube-system", ""}}}
	fl, err := BuildFilterList(context.Background(), f, []OnBuildFilter{&NamespaceFilter{}})
	require.NoError(t, err)
	ev := event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{Process: &tetragon.Process{Pod: &tetragon.Pod{Namespace: "kube-system"}}},
			},
		},
	}
	assert.True(t, fl.MatchOne(&ev))
	ev = event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{Process: &tetragon.Process{Pod: &tetragon.Pod{Namespace: "kube-system"}}},
			},
		},
	}
	assert.True(t, fl.MatchOne(&ev))
	ev = event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{Process: &tetragon.Process{Pod: &tetragon.Pod{Namespace: "kube-system"}}},
			},
		},
	}
	assert.True(t, fl.MatchOne(&ev))
	ev = event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{Process: &tetragon.Process{Pod: &tetragon.Pod{Namespace: "default"}}},
			},
		},
	}
	assert.False(t, fl.MatchOne(&ev))

	ev = event.Event{Event: &tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessExec{ProcessExec: &tetragon.ProcessExec{}}}}
	assert.False(t, fl.MatchOne(&ev))
	ev = event.Event{Event: &tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessExec{ProcessExec: &tetragon.ProcessExec{}}}}
	assert.False(t, fl.MatchOne(&ev))
	ev = event.Event{Event: &tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessExec{ProcessExec: &tetragon.ProcessExec{}}}}
	assert.False(t, fl.MatchOne(&ev))

	// Empty namespace matches process without pod info.
	ev = event.Event{Event: &tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessExec{ProcessExec: &tetragon.ProcessExec{Process: &tetragon.Process{}}}}}
	assert.True(t, fl.MatchOne(&ev))
	ev = event.Event{Event: &tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessExec{ProcessExec: &tetragon.ProcessExec{Process: &tetragon.Process{}}}}}
	assert.True(t, fl.MatchOne(&ev))
	ev = event.Event{Event: &tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessExec{ProcessExec: &tetragon.ProcessExec{Process: &tetragon.Process{}}}}}
	assert.True(t, fl.MatchOne(&ev))
}

func TestNamespaceRegex(t *testing.T) {
	f := []*tetragon.Filter{{NamespaceRegex: []string{"test-.*"}}}
	fl, err := BuildFilterList(context.Background(), f, []OnBuildFilter{&NamespaceRegexFilter{}})
	require.NoError(t, err)

	ev := event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{Process: &tetragon.Process{Pod: &tetragon.Pod{Namespace: "test-app"}}},
			},
		},
	}
	assert.True(t, fl.MatchOne(&ev), "should match test-app namespace")

	ev = event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{Process: &tetragon.Process{Pod: &tetragon.Pod{Namespace: "test-system"}}},
			},
		},
	}
	assert.True(t, fl.MatchOne(&ev), "should match test-system namespace")

	ev = event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{Process: &tetragon.Process{Pod: &tetragon.Pod{Namespace: "kube-system"}}},
			},
		},
	}
	assert.False(t, fl.MatchOne(&ev), "should not match kube-system namespace")

	ev = event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{Process: &tetragon.Process{Pod: &tetragon.Pod{Namespace: "default"}}},
			},
		},
	}
	assert.False(t, fl.MatchOne(&ev), "should not match default namespace")

	ev = event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{Process: &tetragon.Process{}},
			},
		},
	}
	assert.False(t, fl.MatchOne(&ev), "should not match process without pod info")

	ev = event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{},
			},
		},
	}
	assert.False(t, fl.MatchOne(&ev), "should not match nil process")
}

func TestNamespaceRegexMultiplePatterns(t *testing.T) {
	f := []*tetragon.Filter{{NamespaceRegex: []string{"prod-.*", "staging-.*"}}}
	fl, err := BuildFilterList(context.Background(), f, []OnBuildFilter{&NamespaceRegexFilter{}})
	require.NoError(t, err)

	ev := event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{Process: &tetragon.Process{Pod: &tetragon.Pod{Namespace: "prod-app"}}},
			},
		},
	}
	assert.True(t, fl.MatchOne(&ev), "should match prod-app namespace")

	ev = event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{Process: &tetragon.Process{Pod: &tetragon.Pod{Namespace: "staging-app"}}},
			},
		},
	}
	assert.True(t, fl.MatchOne(&ev), "should match staging-app namespace")

	ev = event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{Process: &tetragon.Process{Pod: &tetragon.Pod{Namespace: "dev-app"}}},
			},
		},
	}
	assert.False(t, fl.MatchOne(&ev), "should not match dev-app namespace")
}

func TestNamespaceRegexInvalidPattern(t *testing.T) {
	f := []*tetragon.Filter{{NamespaceRegex: []string{"[invalid"}}}
	_, err := BuildFilterList(context.Background(), f, []OnBuildFilter{&NamespaceRegexFilter{}})
	require.Error(t, err, "should return error for invalid regex")
}
