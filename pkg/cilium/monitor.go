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
	"bytes"
	"context"
	"encoding/gob"
	"net"
	"time"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/monitor"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/monitor/payload"
	"github.com/cilium/hubble/pkg/cilium"
	"github.com/isovalent/tetragon-oss/pkg/logger"
)

// HandleMonitorSocket connects to the monitor socket and consumes monitor events.
func HandleMonitorSocket(ctx context.Context, ciliumState *cilium.State) {
	for {
		conn, err := net.Dial("unix", defaults.MonitorSockPath1_2)
		if err != nil {
			logger.GetLogger().WithError(err).Fatalf("Failed to connect to %s", defaults.MonitorSockPath1_2)
		}
		if err = consumeMonitorEvents(ctx, conn, ciliumState); err != nil {
			logger.GetLogger().WithError(err).Warn("Failed to process monitor event. Reconnecting...")
		}
		if err = conn.Close(); err != nil {
			logger.GetLogger().WithError(err).Warnf("Failed to close %s", defaults.MonitorSockPath1_2)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Second):
		}
	}
}

func consumeMonitorEvents(ctx context.Context, conn net.Conn, ciliumState *cilium.State) error {
	defer conn.Close()
	var pl payload.Payload
	dec := gob.NewDecoder(conn)
	endpointEvents := ciliumState.GetEndpointEventsChannel()
	dnsAdd := ciliumState.GetLogRecordNotifyChannel()
	ipCacheEvents := make(chan monitorAPI.AgentNotify, 100)
	ciliumState.StartMirroringIPCache(ipCacheEvents)
	serviceEvents := make(chan monitorAPI.AgentNotify, 100)
	ciliumState.StartMirroringServiceCache(serviceEvents)
	for {
		if err := pl.DecodeBinary(dec); err != nil {
			return err
		}
		switch pl.Data[0] {
		case monitorAPI.MessageTypeAgent:
			buf := bytes.NewBuffer(pl.Data[1:])
			payloadDecoder := gob.NewDecoder(buf)
			an := monitorAPI.AgentNotify{}
			if err := payloadDecoder.Decode(&an); err != nil {
				logger.GetLogger().WithError(err).Warning("failed to decoded agent notification message")
				continue
			}
			switch an.Type {
			case monitorAPI.AgentNotifyEndpointCreated,
				monitorAPI.AgentNotifyEndpointRegenerateSuccess,
				monitorAPI.AgentNotifyEndpointDeleted:
				endpointEvents <- an
			case monitorAPI.AgentNotifyIPCacheUpserted,
				monitorAPI.AgentNotifyIPCacheDeleted:
				ipCacheEvents <- an
			case monitorAPI.AgentNotifyServiceUpserted,
				monitorAPI.AgentNotifyServiceDeleted:
				serviceEvents <- an
			}
		case monitorAPI.MessageTypeAccessLog:
			// TODO re-think the way this is being done. We are dissecting/
			//      TypeAccessLog messages here *and* when we are dumping
			//      them into JSON.
			buf := bytes.NewBuffer(pl.Data[1:])
			payloadDecoder := gob.NewDecoder(buf)
			lr := monitor.LogRecordNotify{}
			if err := payloadDecoder.Decode(&lr); err != nil {
				logger.GetLogger().WithError(err).Warning("failed to decode access log message type")
				continue
			}
			if lr.DNS != nil {
				dnsAdd <- lr
			}
		}
		select {
		case <-ctx.Done():
			return nil
		default:
		}
	}
}
