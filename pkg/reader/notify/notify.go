package notify

import (
	"fmt"
	"strings"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

type CacheActions struct {
	NeedProcess    bool
	NeedProcessPod bool
	NeedParent     bool
	NeedParentPod  bool
}

// Message is what messages need to implement.
// Moreover, messages may opt to implement the CacheRetry and PostProcessing interfaces (see below).
type Message interface {
	HandleMessage() *tetragon.GetEventsResponse
	Notify() bool
	Cast(o interface{}) Message
}

// CacheRetry may (optionaly) be implemented by messages that requiring custom cache retry functionality.
type CacheRetry interface {
	Retry(Event, *CacheActions, uint32, uint64) error
}

type PostProcessing interface {
	PostProcessing(*tetragon.GetEventsResponse)
}

type Event interface {
	GetProcess() *tetragon.Process
	GetParent() *tetragon.Process
	SetProcess(*tetragon.Process)
	SetParent(*tetragon.Process)
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
