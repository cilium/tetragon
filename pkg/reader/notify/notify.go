package notify

import "github.com/cilium/tetragon/api/v1/tetragon"

type Message interface {
	HandleMessage() *tetragon.GetEventsResponse
}

type Event interface {
	GetProcess() *tetragon.Process
	SetProcess(*tetragon.Process)
	Encapsulate() tetragon.IsGetEventsResponse_Event
}
