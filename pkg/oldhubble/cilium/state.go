// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package cilium

import (
	"github.com/cilium/cilium/pkg/monitor"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	v1 "github.com/cilium/tetragon/pkg/oldhubble/api/v1"
	"github.com/cilium/tetragon/pkg/oldhubble/cilium/client"
	"github.com/cilium/tetragon/pkg/oldhubble/ipcache"
	"github.com/sirupsen/logrus"
)

// State contains various caches for Cilium state and channels to notify
// state changes.
type State struct {
	// Client will connect to Cilium to pool cilium endpoint information
	ciliumClient client.Client

	// endpoints contains a slice of all endpoints running the node where
	// hubble is running.
	endpoints v1.EndpointsHandler

	// FqdnCache contains the responses of all intercepted DNS lookups
	// performed by local endpoints
	fqdnCache FqdnCache

	// ipcache is a mirror of Cilium's IPCache
	ipcache *ipcache.IPCache

	// logRecord is a channel used to exchange L7 DNS requests seens from the
	// monitor
	logRecord chan monitor.LogRecordNotify
	log       *logrus.Entry

	// epAdd is a channel used to exchange endpoint events from Cilium
	endpointEvents chan monitorAPI.AgentNotify
}

// NewCiliumState returns a pointer to an initialized State struct.
func NewCiliumState(
	ciliumClient client.Client,
	endpoints v1.EndpointsHandler,
	ipCache *ipcache.IPCache,
	fqdnCache FqdnCache,
	logger *logrus.Entry,
) *State {
	return &State{
		ciliumClient:   ciliumClient,
		endpoints:      endpoints,
		ipcache:        ipCache,
		fqdnCache:      fqdnCache,
		logRecord:      make(chan monitor.LogRecordNotify, 100),
		endpointEvents: make(chan monitorAPI.AgentNotify, 100),
		log:            logger,
	}
}

// Start starts the server to handle the events sent to the events channel as
// well as handle events to the EpAdd and EpDel channels.
func (s *State) Start() {
	go s.syncEndpoints()
	go s.syncFQDNCache()
	go s.consumeEndpointEvents()
	go s.consumeLogRecordNotifyChannel()
}

// StartMirroringIPCache will obtain an initial IPCache snapshot from Cilium
// and then start mirroring IPCache events based on IPCacheNotification sent
// through the ipCacheEvents channels. Only messages of type
// `AgentNotifyIPCacheUpserted` and `AgentNotifyIPCacheDeleted` should be sent
// through that channel. This function assumes that the caller is already
// connected to Cilium Monitor, i.e. no IPCacheNotification must be lost after
// calling this method.
func (s *State) StartMirroringIPCache(ipCacheEvents <-chan monitorAPI.AgentNotify) {
	go s.syncIPCache(ipCacheEvents)
}

// GetLogRecordNotifyChannel returns the event channel to receive
// monitorAPI.LogRecordNotify events.
func (s *State) GetLogRecordNotifyChannel() chan<- monitor.LogRecordNotify {
	return s.logRecord
}

// GetEndpointEventsChannel returns a channel that should be used to send
// AgentNotifyEndpoint* events when an endpoint is added, deleted or updated
// in Cilium.
func (s *State) GetEndpointEventsChannel() chan<- monitorAPI.AgentNotify {
	return s.endpointEvents
}

// GetCiliumClient returns ciliumClient.
func (s *State) GetCiliumClient() client.Client {
	return s.ciliumClient
}

// GetEndpointsHandler returns endpoints.
func (s *State) GetEndpointsHandler() v1.EndpointsHandler {
	return s.endpoints
}

// GetFQDNCache returns fqdnCache.
func (s *State) GetFQDNCache() FqdnCache {
	return s.fqdnCache
}

// GetIPCache returns ipcache.
func (s *State) GetIPCache() *ipcache.IPCache {
	return s.ipcache
}
