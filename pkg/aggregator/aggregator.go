// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package aggregator

import (
	"sort"
	"strings"
	"time"

	"github.com/cilium/tetragon/api/v1/fgs"
	"github.com/cilium/tetragon/pkg/logger"
)

type Aggregator struct {
	server fgs.FineGuidanceSensors_GetEventsServer
	window time.Duration
	events chan *fgs.GetEventsResponse
	cache  map[string]*fgs.GetEventsResponse
}

func NewAggregator(
	server fgs.FineGuidanceSensors_GetEventsServer,
	options *fgs.AggregationOptions,
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
		make(chan *fgs.GetEventsResponse, options.ChannelBufferSize),
		make(map[string]*fgs.GetEventsResponse),
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
			logger.GetLogger().WithError(err).Warn("Failed to send aggregated response")
		}
	}
	// clear the cache.
	a.cache = make(map[string]*fgs.GetEventsResponse)
}

func (a *Aggregator) handleEvent(event *fgs.GetEventsResponse) {
	switch event.Event.(type) {
	default:
		if err := a.server.Send(event); err != nil {
			logger.GetLogger().WithError(err).Warn("Failed to send unaggregated response")
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

func (a *Aggregator) GetEventChannel() chan *fgs.GetEventsResponse {
	return a.events
}
