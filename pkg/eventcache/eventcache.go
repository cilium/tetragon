// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package eventcache

import (
	"fmt"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/metrics/errormetrics"
	"github.com/cilium/tetragon/pkg/metrics/eventcachemetrics"
	"github.com/cilium/tetragon/pkg/metrics/mapmetrics"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/cilium/tetragon/pkg/server"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// garbage collection states
const (
	threeStrikes = 3
)

// garbage collection run interval
const (
	eventRetryTimer = time.Second * 10
)

var (
	cache    *Cache
	nodeName string
)

type cacheObj struct {
	internal  *process.ProcessInternal
	event     notify.Event
	timestamp *timestamppb.Timestamp
	color     int
	msg       notify.Message
}

type Cache struct {
	objsChan chan cacheObj
	cache    []cacheObj
	server   *server.Server
}

func (ec *Cache) handleNetEvents() {
	tmp := ec.cache[:0]
	for _, e := range ec.cache {
		/* Ensure we actually have a dockerID, we use this for testing reasons
		 * mostly. It is nice though if we ever hit this case to just post it.
		 */
		endpoint := process.GetProcessEndpoint(e.event.GetProcess())
		if e.event.GetProcess().GetDocker() != "" {
			/* If the Pod is nil because process event is incomplete lets
			 * wait and hopefully it is eventually updated from handleProcEvents.
			 */
			if endpoint == nil || e.event.GetProcess().Pod == nil {
				e.color++
				if e.color < threeStrikes {
					tmp = append(tmp, e)
					continue
				}
				errormetrics.EventCacheInc(errormetrics.EventCacheEndpointRetryFailed)
			}
		}

		if e.internal == nil {
			typeName := fmt.Sprintf("%T", e.event)
			eventcachemetrics.ProcessInfoErrorInc(typeName)
			errormetrics.ErrorTotalInc(errormetrics.EventCacheProcessInfoFailed)
		} else {
			e.event.SetProcess(e.internal.GetProcessCopy())
		}

		processedEvent := &tetragon.GetEventsResponse{
			Event:    e.event.Encapsulate(),
			NodeName: nodeName,
			Time:     e.timestamp,
		}

		ec.server.NotifyListeners(e.msg, processedEvent)
	}
	ec.cache = tmp
}

func (ec *Cache) loop() {
	ticker := time.NewTicker(eventRetryTimer)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			/* Every 'eventRetryTimer' walk the slice of events pending pod info. If
			 * an event hasn't completed its podInfo after two iterations send the
			 * event anyways.
			 */
			ec.handleNetEvents()
			mapmetrics.MapSizeSet("netCache", 0, float64(len(ec.cache)))

		case event := <-ec.objsChan:
			errormetrics.EventCacheInc(errormetrics.EventCacheNetworkCount)
			ec.cache = append(ec.cache, event)
		}
	}
}

// We handle two race conditions here one where the event races with
// an TETRAGON execve event and the other -- much more common -- where we
// race with K8s watcher
// case 1 (execve race):
//  Its possible to receive this TETRAGON event before the process event cache
//  has been populated with a TETRAGON execve event. In this case we need to
//  cache the event until the process cache is populated.
// case 2 (k8s watcher race):
//  Its possible to receive an event before the k8s watcher receives the
//  podInfo event and populates the local cache. If we expect podInfo,
//  indicated by having a nonZero dockerID we cache the event until the
//  podInfo arrives.
func (ec *Cache) Needed(proc *tetragon.Process) bool {
	if proc == nil {
		return true
	}
	if proc.Docker != "" && proc.Pod == nil {
		return true
	}
	return false
}

func (ec *Cache) Add(internal *process.ProcessInternal,
	e notify.Event,
	t *timestamppb.Timestamp,
	msg notify.Message) {
	ec.objsChan <- cacheObj{internal: internal, event: e, timestamp: t, msg: msg}
}

func New(s *server.Server) *Cache {
	if cache != nil {
		return cache
	}

	cache = &Cache{
		objsChan: make(chan cacheObj),
		cache:    make([]cacheObj, 0),
		server:   s,
	}
	nodeName = node.GetNodeNameForExport()
	go cache.loop()
	return cache
}

func Get() *Cache {
	return cache
}
