// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package filters

import (
	"context"
	"testing"

	v1 "github.com/cilium/hubble/pkg/api/v1"
	"github.com/isovalent/tetragon-oss/api/v1/fgs"
	"github.com/stretchr/testify/assert"
)

func TestNamespace(t *testing.T) {
	f := []*fgs.Filter{{Namespace: []string{"kube-system", ""}}}
	fl, err := BuildFilterList(context.Background(), f, []OnBuildFilter{&NamespaceFilter{}})
	assert.NoError(t, err)
	ev := v1.Event{
		Event: &fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessExec{
				ProcessExec: &fgs.ProcessExec{Process: &fgs.Process{Pod: &fgs.Pod{Namespace: "kube-system"}}},
			},
		},
	}
	assert.True(t, fl.MatchOne(&ev))
	ev = v1.Event{
		Event: &fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessExec{
				ProcessExec: &fgs.ProcessExec{Process: &fgs.Process{Pod: &fgs.Pod{Namespace: "kube-system"}}},
			},
		},
	}
	assert.True(t, fl.MatchOne(&ev))
	ev = v1.Event{
		Event: &fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessExec{
				ProcessExec: &fgs.ProcessExec{Process: &fgs.Process{Pod: &fgs.Pod{Namespace: "kube-system"}}},
			},
		},
	}
	assert.True(t, fl.MatchOne(&ev))
	ev = v1.Event{
		Event: &fgs.GetEventsResponse{
			Event: &fgs.GetEventsResponse_ProcessExec{
				ProcessExec: &fgs.ProcessExec{Process: &fgs.Process{Pod: &fgs.Pod{Namespace: "default"}}},
			},
		},
	}
	assert.False(t, fl.MatchOne(&ev))

	ev = v1.Event{Event: &fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessExec{ProcessExec: &fgs.ProcessExec{}}}}
	assert.False(t, fl.MatchOne(&ev))
	ev = v1.Event{Event: &fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessExec{ProcessExec: &fgs.ProcessExec{}}}}
	assert.False(t, fl.MatchOne(&ev))
	ev = v1.Event{Event: &fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessExec{ProcessExec: &fgs.ProcessExec{}}}}
	assert.False(t, fl.MatchOne(&ev))

	// Empty namespace matches process without pod info.
	ev = v1.Event{Event: &fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessExec{ProcessExec: &fgs.ProcessExec{Process: &fgs.Process{}}}}}
	assert.True(t, fl.MatchOne(&ev))
	ev = v1.Event{Event: &fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessExec{ProcessExec: &fgs.ProcessExec{Process: &fgs.Process{}}}}}
	assert.True(t, fl.MatchOne(&ev))
	ev = v1.Event{Event: &fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessExec{ProcessExec: &fgs.ProcessExec{Process: &fgs.Process{}}}}}
	assert.True(t, fl.MatchOne(&ev))
}
