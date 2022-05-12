// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package ratelimit

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"time"

	"github.com/isovalent/tetragon-oss/pkg/logger"
	"github.com/isovalent/tetragon-oss/pkg/reader/node"
	"golang.org/x/time/rate"
)

type RateLimiter struct {
	*rate.Limiter
	ctx            context.Context
	reportInterval time.Duration
	dropped        uint64 // accessed atomically
}

// getLimit converts an numEvents and interval to rate.Limit which is a floating point value
// representing number of events per second.
func getLimit(numEvents int, interval time.Duration) rate.Limit {
	if numEvents == 0 {
		return 0
	}
	return rate.Every(interval / time.Duration(numEvents))
}

func NewRateLimiter(ctx context.Context, interval time.Duration, numEvents int, encoder *json.Encoder) *RateLimiter {
	if numEvents < 0 {
		return nil
	}
	r := &RateLimiter{
		rate.NewLimiter(getLimit(numEvents, interval), numEvents),
		ctx,
		interval, // TODO(tk): use a separate interval for reporting?
		0,
	}
	go r.reportRateLimitInfo(encoder)
	return r
}

type Info struct {
	NumberOfDroppedProcessEvents uint64 `json:"number_of_dropped_process_events"`
}

type InfoEvent struct {
	RateLimitInfo *Info     `json:"rate_limit_info"`
	NodeName      string    `json:"node_name"`
	Time          time.Time `json:"time"`
}

func (r *RateLimiter) reportRateLimitInfo(encoder *json.Encoder) {
	ticker := time.NewTicker(r.reportInterval)
	for {
		select {
		case <-ticker.C:
			dropped := atomic.SwapUint64(&r.dropped, 0)
			if dropped > 0 {
				err := encoder.Encode(&InfoEvent{
					RateLimitInfo: &Info{NumberOfDroppedProcessEvents: dropped},
					NodeName:      node.GetNodeNameForExport(),
					Time:          time.Now(),
				})
				if err != nil {
					logger.GetLogger().
						WithError(err).
						WithField("dropped", dropped).
						Warn("Failed to encode rate_limit_info event")
				}
			}
		case <-r.ctx.Done():
			return
		}
	}
}

func (r *RateLimiter) Drop() {
	atomic.AddUint64(&r.dropped, 1)
}
