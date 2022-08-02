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
	"github.com/cilium/tetragon/pkg/option"
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

func handleExecEvent(event *cacheObj, nspid uint32) error {
	var podInfo *tetragon.Pod

	p := event.event.GetProcess()
	containerId := p.Docker
	filename := p.Binary
	args := p.Arguments

	if option.Config.EnableK8s {
		podInfo, _ = process.GetPodInfo(containerId, filename, args, nspid)
		if podInfo == nil {
			errormetrics.ErrorTotalInc(errormetrics.EventCachePodInfoRetryFailed)
			return fmt.Errorf("failed to get pod info")
		}
	}

	event.internal.AddPodInfo(podInfo)
	event.event.SetProcess(event.internal.GetProcessCopy())

	return nil
}

func handleEvent(event *cacheObj) error {
	p := event.event.GetProcess()

	// If the process wasn't found before the Add(), likely because
	// the execve event was processed after this event, lets look it up
	// now because it should be available. Otherwise we have a valid
	// process and lets copy it across.
	if event.internal == nil {
		event.internal, _ = process.GetParentProcessInternal(p.Pid.Value, p.StartTime.Value) //tbd StartTime needs to be the correct uint64 not the mangled timestamp.
		if event.internal == nil {
			return fmt.Errorf("Process lookup failed")
		}
	}

	event.event.SetProcess(event.internal.GetProcessCopy())
	return nil
}

func (ec *Cache) handleEvents() {
	tmp := ec.cache[:0]
	for _, event := range ec.cache {
		var err error
		if getNsPid, ok := event.msg.(interface{ GetNsPid() uint32 }); ok {
			nspid := getNsPid.GetNsPid()
			err = handleExecEvent(&event, nspid)
		} else {
			err = handleEvent(&event)
		}

		if err != nil {
			event.color++
			if event.color < threeStrikes {
				tmp = append(tmp, event)
				continue
			}
		}

		processedEvent := &tetragon.GetEventsResponse{
			Event:    event.event.Encapsulate(),
			NodeName: nodeName,
			Time:     event.timestamp,
		}

		ec.server.NotifyListeners(event.msg, processedEvent)
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
			ec.handleEvents()
			mapmetrics.MapSizeSet("eventcache", 0, float64(len(ec.cache)))

		case event := <-ec.objsChan:
			eventcachemetrics.EventCacheCount.Inc()
			ec.cache = append(ec.cache, event)
		}
	}
}

// We handle two race conditions here one where the event races with
// a Tetragon execve event and the other -- much more common -- where we
// race with K8s watcher
// case 1 (execve race):
//  Its possible to receive this Tetragon event before the process event cache
//  has been populated with a Tetragon execve event. In this case we need to
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
	if option.Config.EnableK8s {
		if proc.Docker != "" && proc.Pod == nil {
			return true
		}
	}
	if proc.Binary == "" {
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
