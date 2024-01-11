// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package filters

import (
	"context"
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	v1 "github.com/cilium/tetragon/pkg/oldhubble/api/v1"
	"github.com/stretchr/testify/assert"
)

func TestPolicyNamesFilterInvalidEvent(t *testing.T) {
	ctx := context.Background()
	filters := []*tetragon.Filter{{PolicyNames: []string{"red-policy"}}}
	filterFuncs := []OnBuildFilter{&PolicyNamesFilter{}}
	fs, err := BuildFilterList(ctx, filters, filterFuncs)
	assert.NoError(t, err)
	ev := v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessKprobe{
				ProcessKprobe: &tetragon.ProcessKprobe{},
			},
		},
	}
	assert.False(t, fs.MatchOne(&ev))
}

func TestPolicyNamesFilterCorrectValue(t *testing.T) {
	ctx := context.Background()
	filters := []*tetragon.Filter{{PolicyNames: []string{"red-policy", "blue-policy"}}}
	filterFuncs := []OnBuildFilter{&PolicyNamesFilter{}}
	fs, err := BuildFilterList(ctx, filters, filterFuncs)
	assert.NoError(t, err)
	ev := v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessKprobe{
				ProcessKprobe: &tetragon.ProcessKprobe{
					PolicyName: "red-policy",
				},
			},
		},
	}
	assert.True(t, fs.MatchOne(&ev))
	ev = v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessKprobe{
				ProcessKprobe: &tetragon.ProcessKprobe{
					PolicyName: "blue-policy",
				},
			},
		},
	}
	assert.True(t, fs.MatchOne(&ev))
	ev = v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessKprobe{
				ProcessKprobe: &tetragon.ProcessKprobe{
					PolicyName: "yellow-policy",
				},
			},
		},
	}
	assert.False(t, fs.MatchOne(&ev))
}

func TestPolicyNamesFilterEmptyValue(t *testing.T) {
	ctx := context.Background()
	filters := []*tetragon.Filter{{PolicyNames: []string{""}}}
	filterFuncs := []OnBuildFilter{&PolicyNamesFilter{}}
	fs, err := BuildFilterList(ctx, filters, filterFuncs)
	assert.NoError(t, err)
	// empty selector matches nothing
	ev := v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessKprobe{
				ProcessKprobe: &tetragon.ProcessKprobe{
					PolicyName: "red-policy",
				},
			},
		},
	}
	assert.False(t, fs.MatchOne(&ev))
}

func TestPolicyNamesFilterNilValue(t *testing.T) {
	ctx := context.Background()
	filters := []*tetragon.Filter{{PolicyNames: nil}}
	filterFuncs := []OnBuildFilter{&PolicyNamesFilter{}}
	fs, err := BuildFilterList(ctx, filters, filterFuncs)
	assert.NoError(t, err)
	// nil selector matches everything, i.e., does not filter events
	ev := v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessKprobe{
				ProcessKprobe: &tetragon.ProcessKprobe{
					PolicyName: "red-policy",
				},
			},
		},
	}
	assert.True(t, fs.MatchOne(&ev))
}
