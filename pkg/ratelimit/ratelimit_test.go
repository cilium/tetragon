// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package ratelimit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

func Test_getLimit(t *testing.T) {
	eps := 1e-9

	assert.InDelta(t, float64(rate.Limit(0)), float64(getLimit(0, time.Minute)), eps)
	assert.InDelta(t, float64(rate.Limit(0)), float64(getLimit(0, 0)), eps)
	assert.InEpsilon(t, float64(rate.Limit(1)), float64(getLimit(60, time.Minute)), eps)
	assert.InEpsilon(t, float64(rate.Limit(10.0/60)), float64(getLimit(10, time.Minute)), eps)
	// 1/ms => 1000/second
	assert.InEpsilon(t, float64(rate.Limit(1000)), float64(getLimit(1, time.Millisecond)), eps)
	// 3600/hour => 1/second
	assert.InEpsilon(t, float64(rate.Limit(1)), float64(getLimit(60*60, time.Hour)), eps)

	// interval<=0 => infinite rate limit (allow all events)
	assert.InEpsilon(t, float64(rate.Inf), float64(getLimit(1, 0)), eps)
	assert.InEpsilon(t, float64(rate.Inf), float64(getLimit(1, -1)), eps)
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
