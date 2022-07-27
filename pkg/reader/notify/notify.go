package notify

import "github.com/cilium/tetragon/api/v1/tetragon"

type Message interface {
	HandleMessage() *tetragon.GetEventsResponse
}
