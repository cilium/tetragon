// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package filters

import (
	"context"
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/event"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPodRegexFilterBasic(t *testing.T) {
	f := []*tetragon.Filter{{PodRegex: []string{"client", "server"}}}
	fl, err := BuildFilterList(context.Background(), f, []OnBuildFilter{&PodRegexFilter{}})
	require.NoError(t, err)
	ev := event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{
					Process: &tetragon.Process{
						Pod: &tetragon.Pod{
							Name: "client",
						},
					},
				},
			},
		},
	}
	assert.True(t, fl.MatchOne(&ev))
	ev = event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{
					Process: &tetragon.Process{
						Pod: &tetragon.Pod{
							Name: "client-deadb33f",
						},
					},
				},
			},
		},
	}
	assert.True(t, fl.MatchOne(&ev))
	ev = event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{
					Process: &tetragon.Process{
						Pod: &tetragon.Pod{
							Name: "server",
						},
					},
				},
			},
		},
	}
	assert.True(t, fl.MatchOne(&ev))
	ev = event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{
					Process: &tetragon.Process{
						Pod: &tetragon.Pod{
							Name: "server-deadb33f",
						},
					},
				},
			},
		},
	}
	assert.True(t, fl.MatchOne(&ev))
	ev = event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessKprobe{
				ProcessKprobe: &tetragon.ProcessKprobe{
					Process: &tetragon.Process{
						Pod: &tetragon.Pod{
							Name: "kube-proxy",
						},
					},
				},
			},
		},
	}
	assert.False(t, fl.MatchOne(&ev))
}

func TestPodRegexFilterAdvanced(t *testing.T) {
	f := []*tetragon.Filter{{PodRegex: []string{"client.*", "^server$"}}}
	fl, err := BuildFilterList(context.Background(), f, []OnBuildFilter{&PodRegexFilter{}})
	require.NoError(t, err)
	ev := event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{
					Process: &tetragon.Process{
						Pod: &tetragon.Pod{
							Name: "client",
						},
					},
				},
			},
		},
	}
	assert.True(t, fl.MatchOne(&ev))
	ev = event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{
					Process: &tetragon.Process{
						Pod: &tetragon.Pod{
							Name: "client-deadb33f",
						},
					},
				},
			},
		},
	}
	assert.True(t, fl.MatchOne(&ev))
	ev = event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{
					Process: &tetragon.Process{
						Pod: &tetragon.Pod{
							Name: "server",
						},
					},
				},
			},
		},
	}
	assert.True(t, fl.MatchOne(&ev))
	ev = event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{
					Process: &tetragon.Process{
						Pod: &tetragon.Pod{
							Name: "server-ab41ed2",
						},
					},
				},
			},
		},
	}
	assert.False(t, fl.MatchOne(&ev))
	ev = event.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessKprobe{
				ProcessKprobe: &tetragon.ProcessKprobe{
					Process: &tetragon.Process{
						Pod: &tetragon.Pod{
							Name: "kube-proxy",
						},
					},
				},
			},
		},
	}
	assert.False(t, fl.MatchOne(&ev))
}

func TestPodRegexFilterInvalidRegex(t *testing.T) {
	f := []*tetragon.Filter{{PodRegex: []string{"*"}}}
	_, err := BuildFilterList(context.Background(), f, []OnBuildFilter{&PodRegexFilter{}})
	require.Error(t, err)
}

func TestPodRegexFilterInvalidEvent(t *testing.T) {
	f := []*tetragon.Filter{{PodRegex: []string{".*"}}}
	fl, err := BuildFilterList(context.Background(), f, []OnBuildFilter{&PodRegexFilter{}})
	require.NoError(t, err)
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
		Event: &tetragon.GetEventsResponse_ProcessKprobe{ProcessKprobe: &tetragon.ProcessKprobe{Process: nil}},
	}}))
}
