// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package client

import (
	"sort"
	"strconv"

	ciliumEP "github.com/cilium/cilium/api/v1/client/endpoint"
	ciliumPolicy "github.com/cilium/cilium/api/v1/client/policy"
	"github.com/cilium/cilium/api/v1/models"
	clientPkg "github.com/cilium/cilium/pkg/client"
)

// Client is the interface for Cilium API.
type Client interface {
	EndpointList() ([]*models.Endpoint, error)
	GetEndpoint(id uint64) (*models.Endpoint, error)
	GetIdentity(id uint64) (*models.Identity, error)
	GetFqdnCache() ([]*models.DNSLookup, error)
	GetIPCache() ([]*models.IPListEntry, error)
	GetServiceCache() ([]*models.Service, error)
}

// Cilium is an abstraction to communicate with the cilium-agent.
type Cilium struct {
	*clientPkg.Client
}

// NewClient returns a new Cilium client that will connect to the cilium-agent.
func NewClient() (*Cilium, error) {
	ciliumClient, err := clientPkg.NewClient("")
	if err != nil {
		return nil, err
	}
	return &Cilium{
		Client: ciliumClient,
	}, nil
}

// GetEndpoint returns the endpoint with the given ID from the cilium-agent.
func (c *Cilium) GetEndpoint(id uint64) (*models.Endpoint, error) {
	cep, err := c.Client.Endpoint.GetEndpointID(ciliumEP.NewGetEndpointIDParams().WithID(strconv.FormatUint(id, 10)))
	if err != nil {
		return nil, err
	}
	return cep.Payload, nil
}

func sortIdentityLabels(identity *models.Identity) {
	sort.Strings(identity.Labels)
}

// GetIdentity returns security identity information for a given identity.
func (c *Cilium) GetIdentity(id uint64) (*models.Identity, error) {
	identity, err := c.Client.IdentityGet(strconv.FormatUint(id, 10))
	if err != nil {
		return nil, err
	}
	sortIdentityLabels(identity)
	return identity, nil
}

// GetFqdnCache retrieves the list of DNS lookups intercepted from all endpoints.
func (c *Cilium) GetFqdnCache() ([]*models.DNSLookup, error) {
	cache, err := c.Client.Policy.GetFqdnCache(nil)
	if err != nil {
		// GetFqdnCache returns 404 if the cache is empty.
		if _, ok := err.(*ciliumPolicy.GetFqdnCacheNotFound); ok {
			return nil, nil
		}
		return nil, err
	}
	return cache.Payload, nil
}

// GetIPCache retrieves the contents of the Cilium ipcache
func (c *Cilium) GetIPCache() ([]*models.IPListEntry, error) {
	ips, err := c.Client.Policy.GetIP(nil)
	if err != nil {
		return nil, err
	}
	return ips.Payload, nil
}

// GetServiceCache retrieves the contents of the Cilium service cache.
func (c *Cilium) GetServiceCache() ([]*models.Service, error) {
	svcs, err := c.Client.Service.GetService(nil)
	if err != nil {
		return nil, err
	}
	return svcs.Payload, nil
}

// IsIPCacheNotFoundErr is true if the IPCache fetch error was a 404
func IsIPCacheNotFoundErr(err error) bool {
	_, ok := err.(*ciliumPolicy.GetIPNotFound)
	return ok
}
