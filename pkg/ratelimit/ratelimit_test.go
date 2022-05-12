// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package ratelimit

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.org/x/time/rate"
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
	ev := InfoEvent{
		RateLimitInfo: &Info{NumberOfDroppedProcessEvents: 10},
		NodeName:      "my-node",
		Time:          time.Time{},
	}
	b, err := json.Marshal(ev)
	assert.NoError(t, err)
	assert.Equal(t, `{"rate_limit_info":{"number_of_dropped_process_events":10},"node_name":"my-node","time":"0001-01-01T00:00:00Z"}`, string(b))
}
