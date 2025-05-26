// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package ratelimit

import (
	"testing"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func Test_getLimit(t *testing.T) {
	assert.Equal(t, rate.Limit(0), getLimit(0, time.Minute))
	assert.Equal(t, rate.Limit(0), getLimit(0, 0))
	assert.Equal(t, rate.Limit(1), getLimit(60, time.Minute))
	assert.Equal(t, rate.Limit(10.0/60), getLimit(10, time.Minute))
	// 1/ms => 1000/second
	assert.Equal(t, rate.Limit(1000), getLimit(1, time.Millisecond))
	// 3600/hour => 1/second
	assert.Equal(t, rate.Limit(1), getLimit(60*60, time.Hour))

	// interval<=0 => infinite rate limit (allow all events)
	assert.Equal(t, rate.Inf, getLimit(1, 0))
	assert.Equal(t, rate.Inf, getLimit(1, -1))
}

func Test_rateLimitJSON(t *testing.T) {
	ev := &tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_RateLimitInfo{
			RateLimitInfo: &tetragon.RateLimitInfo{
				NumberOfDroppedProcessEvents: 10,
			},
		},
		NodeName: "my-node",
		Time:     timestamppb.New(time.Time{}),
	}
	b, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(ev)
	require.NoError(t, err)

	ev2 := &tetragon.GetEventsResponse{}
	err = ev2.UnmarshalJSON(b)
	require.NoError(t, err)

	assert.Equal(t, ev, ev2)
}
