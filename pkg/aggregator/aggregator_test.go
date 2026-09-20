// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package aggregator

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

func Test_getNameOrIp(t *testing.T) {
	assert.Equal(t, "1.1.1.1", getNameOrIp("1.1.1.1", []string{}))
	assert.Equal(t, "a.com,b.com,c.com", getNameOrIp("1.1.1.1", []string{"b.com", "c.com", "a.com"}))
}

func TestAggregatorStopsWhenContextIsCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	a := &Aggregator{
		window: time.Hour,
		events: make(chan *tetragon.GetEventsResponse),
	}

	go func() {
		a.Start(ctx)
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Aggregator did not stop after context cancellation")
	}
}
