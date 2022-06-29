package notify

import "github.com/cilium/tetragon/api/v1/tetragon"

type Interface interface {
	HandleMessage() *tetragon.GetEventsResponse
}
