package notify

import (
	"fmt"
	"strings"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

type Message interface {
	HandleMessage() *tetragon.GetEventsResponse
}

type Event interface {
	GetProcess() *tetragon.Process
	SetProcess(*tetragon.Process)
	Encapsulate() tetragon.IsGetEventsResponse_Event
}

func EventTypeString(event Event) string {
	// Get the concrete type of the event
	ty := fmt.Sprintf("%T", event)
	// Take only what comes after the last "."
	tys := strings.Split(ty, ".")
	ty = tys[len(tys)-1]
	return ty
}
