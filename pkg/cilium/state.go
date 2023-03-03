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
	"github.com/cilium/tetragon/pkg/logger"
	v1 "github.com/cilium/tetragon/pkg/oldhubble/api/v1"
	"github.com/cilium/tetragon/pkg/oldhubble/cilium"
	"github.com/cilium/tetragon/pkg/oldhubble/cilium/client"
	"github.com/cilium/tetragon/pkg/oldhubble/fqdncache"
	"github.com/cilium/tetragon/pkg/oldhubble/ipcache"
	"github.com/cilium/tetragon/pkg/oldhubble/servicecache"
)

var (
	ciliumState *cilium.State
)

func GetCiliumState() *cilium.State {
	return ciliumState
}

func InitCiliumState(ctx context.Context, enableCiliumAPI bool) (*cilium.State, error) {
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
		ciliumState = cilium.NewCiliumState(
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

func GetFakeCiliumState() *cilium.State {
	return cilium.NewCiliumState(
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
