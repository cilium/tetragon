// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cilium

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/monitor"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	v1 "github.com/cilium/hubble/pkg/api/v1"
	"github.com/cilium/hubble/pkg/fqdncache"
	"github.com/cilium/hubble/pkg/ipcache"
	"github.com/cilium/tetragon/pkg/cilium/client"
	"github.com/cilium/tetragon/pkg/cilium/servicecache"
	"github.com/cilium/tetragon/pkg/logger"
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

	// serviceCache is a cache that contains information about services.
	serviceCache *servicecache.ServiceCache

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
	serviceCache *servicecache.ServiceCache,
	logger *logrus.Entry,
) *State {
	return &State{
		ciliumClient: ciliumClient,
		endpoints:    endpoints,
		ipcache:      ipCache,
		fqdnCache:    fqdnCache, serviceCache: serviceCache,
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

// StartMirroringServiceCache initially caches service information from Cilium
// and then starts to mirror service information based on events that are sent
// to the serviceEvents channel. Only messages of type
// `AgentNotifyServiceUpserted` and `AgentNotifyServiceDeleted` should be sent
// to this channel.  This function assumes that the caller is already connected
// to Cilium Monitor, i.e. no Service notification must be lost after calling
// this method.
func (s *State) StartMirroringServiceCache(serviceEvents <-chan monitorAPI.AgentNotify) {
	go s.syncServiceCache(serviceEvents)
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

// GetServiceCache returns serviceCache.
func (s *State) GetServiceCache() *servicecache.ServiceCache {
	return s.serviceCache
}

var (
	ciliumState *State
)

func GetCiliumState() *State {
	return ciliumState
}

func InitCiliumState(ctx context.Context, enableCiliumAPI bool) (*State, error) {
	if ciliumState != nil {
		return ciliumState, nil
	}
	if !enableCiliumAPI {
		logger.GetLogger().Info("Disabling Cilium API")
		ciliumState = GetFakeCiliumState()
	} else {
		logger.GetLogger().Info("Enabling Cilium API")
		ciliumClient, err := client.NewClient()
		if err != nil {
			return nil, fmt.Errorf("failed to get Cilium client: %v", err)
		}
		ciliumState = NewCiliumState(
			ciliumClient,
			v1.NewEndpoints(),
			ipcache.New(),
			fqdncache.New(),
			servicecache.New(),
			logger.GetLogger().WithField("subsystem", "cilium"))
		go ciliumState.Start()
		go HandleMonitorSocket(ctx, ciliumState)
	}
	return ciliumState, nil
}

func GetFakeCiliumState() *State {
	return NewCiliumState(
		&fakeCiliumClient{},
		v1.NewEndpoints(),
		ipcache.New(),
		fqdncache.New(),
		servicecache.New(),
		logger.GetLogger().WithField("subsystem", "cilium"))
}

type fakeCiliumClient struct{}

func (f fakeCiliumClient) EndpointList() ([]*models.Endpoint, error) {
	return nil, nil
}

func (f fakeCiliumClient) GetEndpoint(id uint64) (*models.Endpoint, error) {
	return nil, fmt.Errorf("endpoint with id %d not found", id)
}

func (f fakeCiliumClient) GetIdentity(id uint64) (*models.Identity, error) {
	return nil, fmt.Errorf("identity with id %d not found", id)
}

func (f fakeCiliumClient) GetFqdnCache() ([]*models.DNSLookup, error) {
	return nil, nil
}

func (f fakeCiliumClient) GetIPCache() ([]*models.IPListEntry, error) {
	return nil, nil
}

func (f fakeCiliumClient) GetServiceCache() ([]*models.Service, error) {
	return nil, nil
}
