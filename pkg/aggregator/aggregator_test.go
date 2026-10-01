// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package aggregator

import (
	"context"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

func Test_getNameOrIp(t *testing.T) {
	assert.Equal(t, "1.1.1.1", getNameOrIp("1.1.1.1", []string{}))
	assert.Equal(t, "a.com,b.com,c.com", getNameOrIp("1.1.1.1", []string{"b.com", "c.com", "a.com"}))
}

type stubServer struct {
	grpc.ServerStream
	sent atomic.Int32
}

func (s *stubServer) Send(*tetragon.GetEventsResponse) error {
	s.sent.Add(1)
	return nil
}

func newTestAggregator() (*Aggregator, error) {
	return NewAggregator(&stubServer{}, &tetragon.AggregationOptions{
		WindowSize:        durationpb.New(time.Hour),
		ChannelBufferSize: 10,
	})
}

// Abandoned aggregators must exit once their context is done instead
// of leaking the goroutine and its ticker forever. synctest.Test
// only returns after every goroutine in the bubble exits, so a leaked
// Run fails this test by deadlocking it.
func TestAggregatorStopsOnCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		for range 3 {
			agg, err := newTestAggregator()
			require.NoError(t, err)
			go agg.Run(ctx)
		}
		synctest.Wait()
		cancel()
	})
}

// Events flowing through an aggregator are forwarded as they arrive
// (pass-through); stopping behaviour is covered by the tests below.
func TestAggregatorForwardsEventsPassThrough(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		stub := &stubServer{}
		ctx, cancel := context.WithCancel(t.Context())
		agg, err := NewAggregator(stub, &tetragon.AggregationOptions{
			WindowSize:        durationpb.New(time.Hour),
			ChannelBufferSize: 10,
		})
		require.NoError(t, err)
		go agg.Run(ctx)
		agg.GetEventChannel() <- &tetragon.GetEventsResponse{}
		agg.GetEventChannel() <- &tetragon.GetEventsResponse{}
		synctest.Wait()
		require.Equal(t, int32(2), stub.sent.Load())
		cancel()
	})
}

// Events already aggregated in the cache must be delivered on stop,
// not dropped with the exiting goroutine.
func TestAggregatorFlushesPendingCacheOnStop(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		stub := &stubServer{}
		ctx, cancel := context.WithCancel(t.Context())
		agg, err := NewAggregator(stub, &tetragon.AggregationOptions{
			WindowSize:        durationpb.New(time.Hour),
			ChannelBufferSize: 10,
		})
		require.NoError(t, err)
		// Prime the cache by hand: handleEvent only Sends (default-only
		// switch), so production traffic never fills the cache — seeding
		// is the only way to reach the flush path.
		agg.cache["pending-key"] = &tetragon.GetEventsResponse{}
		go agg.Run(ctx)
		cancel()
		synctest.Wait()
		require.Equal(t, int32(1), stub.sent.Load())
		require.Empty(t, agg.cache)
	})
}
