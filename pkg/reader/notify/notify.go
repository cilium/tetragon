// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package notify

import (
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/process"
)

type Message interface {
	HandleMessage() *tetragon.GetEventsResponse
	RetryInternal(Event, uint64) (*process.ProcessInternal, error)
	Retry(*process.ProcessInternal, Event) error
	Notify() bool
	Cast(o interface{}) Message
}

type Event interface {
	GetProcess() *tetragon.Process
	GetParent() *tetragon.Process
	GetAncestors() []*tetragon.Process
	SetProcess(*tetragon.Process)
	SetParent(*tetragon.Process)
	SetAncestors([]*tetragon.Process)
	Encapsulate() tetragon.IsGetEventsResponse_Event
}

func EventType(event Event) tetragon.EventType {
	if event == nil {
		return tetragon.EventType_UNDEF
	}
	eventWrapper := event.Encapsulate()
	res := &tetragon.GetEventsResponse{
		Event: eventWrapper,
	}
	return res.EventType()
}
