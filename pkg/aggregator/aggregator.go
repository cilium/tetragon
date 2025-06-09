// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package aggregator

import (
	"sort"
	"strings"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
)

type Aggregator struct {
	server tetragon.FineGuidanceSensors_GetEventsServer
	window time.Duration
	events chan *tetragon.GetEventsResponse
	cache  map[string]*tetragon.GetEventsResponse
}

func NewAggregator(
	server tetragon.FineGuidanceSensors_GetEventsServer,
	options *tetragon.AggregationOptions,
) (*Aggregator, error) {
	if options == nil {
		return nil, nil
	}
	window := 15 * time.Second
	if options.WindowSize != nil {
		window = options.WindowSize.AsDuration()
	}
	return &Aggregator{
		server,
		window,
		make(chan *tetragon.GetEventsResponse, options.ChannelBufferSize),
		make(map[string]*tetragon.GetEventsResponse),
	}, nil
}

func (a *Aggregator) Start() {
	// nolint Since Aggregator.Start is an endless function,
	// this qualifies as an acceptable use of time.Tick
	tick := time.Tick(a.window)
	for {
		select {
		case event := <-a.events:
			a.handleEvent(event)
		case <-tick:
			a.flush()
		}
	}
}

func (a *Aggregator) flush() {
	for _, event := range a.cache {
		if err := a.server.Send(event); err != nil {
			logger.GetLogger().Warn("Failed to send aggregated response", logfields.Error, err)
		}
	}
	// clear the cache.
	a.cache = make(map[string]*tetragon.GetEventsResponse)
}

func (a *Aggregator) handleEvent(event *tetragon.GetEventsResponse) {
	switch event.Event.(type) {
	default:
		if err := a.server.Send(event); err != nil {
			logger.GetLogger().Warn("Failed to send unaggregated response", logfields.Error, err)
		}
	}
}

func getNameOrIp(ip string, names []string) string {
	if len(names) > 0 {
		sort.Strings(names)
		return strings.Join(names, ",")
	}
	return ip
}

func (a *Aggregator) GetEventChannel() chan *tetragon.GetEventsResponse {
	return a.events
}
