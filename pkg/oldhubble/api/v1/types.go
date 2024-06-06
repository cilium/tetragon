// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package v1

import (
	"net"
	"sync"

	"github.com/cilium/cilium/pkg/identity"
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
