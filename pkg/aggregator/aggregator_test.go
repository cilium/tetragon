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

type blockingGetEventsServer struct {
	tetragon.FineGuidanceSensors_GetEventsServer
	sendStarted chan struct{}
	releaseSend chan struct{}
}

type recordingGetEventsServer struct {
	tetragon.FineGuidanceSensors_GetEventsServer
	sent chan *tetragon.GetEventsResponse
}

func (s *recordingGetEventsServer) Send(event *tetragon.GetEventsResponse) error {
	s.sent <- event
	return nil
}

func (s *blockingGetEventsServer) Send(*tetragon.GetEventsResponse) error {
	close(s.sendStarted)
	<-s.releaseSend
	return nil
}

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

func TestAggregatorNonPositiveWindow(t *testing.T) {
	for _, window := range []time.Duration{0, -time.Second} {
		t.Run(window.String(), func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			server := &recordingGetEventsServer{
				sent: make(chan *tetragon.GetEventsResponse, 1),
			}
			a := &Aggregator{
				server: server,
				window: window,
				events: make(chan *tetragon.GetEventsResponse, 1),
			}
			done := make(chan any, 1)
			go func() {
				defer func() {
					done <- recover()
				}()
				a.Start(ctx)
			}()

			event := &tetragon.GetEventsResponse{}
			a.events <- event
			select {
			case sent := <-server.sent:
				assert.Same(t, event, sent)
			case <-time.After(time.Second):
				t.Fatal("Aggregator did not process event with non-positive window")
			}
			cancel()
			select {
			case panicValue := <-done:
				assert.Nil(t, panicValue)
			case <-time.After(time.Second):
				t.Fatal("Aggregator did not stop after context cancellation")
			}
		})
	}
}

func TestAggregatorStopsAfterCanceledBlockedSendReturns(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	server := &blockingGetEventsServer{
		sendStarted: make(chan struct{}),
		releaseSend: make(chan struct{}),
	}
	a := &Aggregator{
		server: server,
		window: time.Hour,
		events: make(chan *tetragon.GetEventsResponse, 1),
	}
	done := make(chan struct{})
	go func() {
		a.Start(ctx)
		close(done)
	}()

	a.events <- &tetragon.GetEventsResponse{}
	select {
	case <-server.sendStarted:
	case <-time.After(time.Second):
		t.Fatal("Aggregator did not enter the blocked send")
	}
	cancel()
	select {
	case <-done:
		t.Fatal("Aggregator returned before the blocked send was released")
	default:
	}
	close(server.releaseSend)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Aggregator did not stop after the canceled send returned")
	}
}
