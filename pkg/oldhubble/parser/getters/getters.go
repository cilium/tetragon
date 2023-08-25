// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package getters

import (
	"net"

	pb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/tetragon/pkg/oldhubble/api/v1"
	"github.com/cilium/tetragon/pkg/oldhubble/ipcache"

	"github.com/cilium/cilium/api/v1/models"
)

// DNSGetter ...
type DNSGetter interface {
	// GetNamesOf fetches FQDNs of a given IP from the perspective of
	// the endpoint with ID sourceEpID
	GetNamesOf(sourceEpID uint64, ip net.IP) (names []string)
}

// EndpointGetter ...
type EndpointGetter interface {
	// GetEndpointInfo looks up endpoint by IP address.
	GetEndpointInfo(ip net.IP) (endpoint v1.EndpointInfo, ok bool)
}

// IdentityGetter ...
type IdentityGetter interface {
	// GetIdentity fetches a full identity object given a numeric security id.
	GetIdentity(id uint64) (*models.Identity, error)
}

// IPGetter fetches per-IP metadata
type IPGetter interface {
	// GetIPIdentity fetches information known about a remote IP.
	GetIPIdentity(ip net.IP) (identity ipcache.IPIdentity, ok bool)
}

// ServiceGetter fetches service metadata.
type ServiceGetter interface {
	GetServiceByAddr(ip net.IP, port uint16) (service pb.Service, ok bool)
}
