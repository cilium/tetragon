// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package ratelimit

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/encoder"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/reader/node"
	"golang.org/x/time/rate"
	"google.golang.org/protobuf/types/known/timestamppb"
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

func NewRateLimiter(ctx context.Context, interval time.Duration, numEvents int, encoder encoder.EventEncoder) *RateLimiter {
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

func (r *RateLimiter) reportRateLimitInfo(encoder encoder.EventEncoder) {
	ticker := time.NewTicker(r.reportInterval)
	for {
		select {
		case <-ticker.C:
			dropped := atomic.SwapUint64(&r.dropped, 0)
			if dropped > 0 {
				ev := tetragon.GetEventsResponse{
					Event: &tetragon.GetEventsResponse_RateLimitInfo{
						RateLimitInfo: &tetragon.RateLimitInfo{
							NumberOfDroppedProcessEvents: dropped,
						},
					},
					Time: timestamppb.New(time.Now()),
				}
				node.SetCommonFields(&ev)
				err := encoder.Encode(&ev)
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
