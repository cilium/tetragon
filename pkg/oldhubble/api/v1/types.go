// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package v1

import (
	"net"
	"sync"

	pb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/gogo/protobuf/types"
)

// Endpoint is the representation of an endpoint running in the Cilium agent
type Endpoint struct {
	ContainerIDs []string                 `json:"container-ids"`
	ID           uint64                   `json:"id"`
	Identity     identity.NumericIdentity `json:"identity"`
	IPv4         net.IP                   `json:"ipv4"`
	IPv6         net.IP                   `json:"ipv6"`
	PodName      string                   `json:"pod-name"`
	PodNamespace string                   `json:"pod-namespace"`
	Labels       []string                 `json:"labels"`
}

// GetID returns the ID of the endpoint.
func (e *Endpoint) GetID() uint64 {
	return e.ID
}

// GetIdentity returns the numerical security identity of the endpoint.
func (e *Endpoint) GetIdentity() identity.NumericIdentity {
	return e.Identity
}

// GetK8sPodName returns the pod name of the endpoint.
func (e *Endpoint) GetK8sPodName() string {
	return e.PodName
}

// GetK8sNamespace returns the pod namespace of the endpoint.
func (e *Endpoint) GetK8sNamespace() string {
	return e.PodNamespace
}

// GetLabels returns the labels of the endpoint.
func (e *Endpoint) GetLabels() []string {
	return e.Labels
}

// Event represents a single event observed and stored by Hubble
type Event struct {
	// Timestamp when event was observed in Hubble
	Timestamp *types.Timestamp
	// Event contains the actual event
	Event interface{}
}

// GetFlow returns the decoded flow, or nil if there is no event
func (ev *Event) GetFlow() Flow {
	if ev == nil || ev.Event == nil {
		// returns typed nil so getter methods still work
		return (*pb.Flow)(nil)
	}
	if f, ok := ev.Event.(Flow); ok {
		return f
	}
	return nil
}

// Endpoints is a slice of endpoints and their cached dns queries protected by a mutex.
type Endpoints struct {
	mutex sync.RWMutex
	eps   []*Endpoint
}

// NewEndpoints returns a new *Endpoints.
func NewEndpoints() *Endpoints {
	return &Endpoints{
		eps: []*Endpoint{},
	}
}
