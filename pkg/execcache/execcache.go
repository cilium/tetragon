// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package execcache

import (
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/metrics/errormetrics"
	"github.com/cilium/tetragon/pkg/metrics/mapmetrics"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/node"
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
	process   *tetragon.ProcessExec
	timestamp *timestamppb.Timestamp
	color     int
	msg       *processapi.MsgExecveEventUnix
}

type Cache struct {
	objsChan chan cacheObj
	objs     []cacheObj
	server   *server.Server
}

func handleExecEvents() {
	tmp := cache.objs[:0]
	for _, e := range cache.objs {
		containerId := e.process.Process.Docker
		filename := e.process.Process.Binary
		args := e.process.Process.Arguments
		nspid := e.msg.Process.NSPID

		podInfo, _ := process.GetPodInfo(containerId, filename, args, nspid)
		if podInfo == nil {
			e.color++
			if e.color != threeStrikes {
				tmp = append(tmp, e)
				continue
			}
			errormetrics.EventCacheInc(errormetrics.EventCachePodInfoRetryFailed)
		}

		if e.internal != nil {
			e.internal.AddPodInfo(podInfo)
			e.process.Process = e.internal.GetProcessCopy()
		} else {
			e.process.Process.Pod = podInfo
		}

		processedEvent := &tetragon.GetEventsResponse{
			Event:    &tetragon.GetEventsResponse_ProcessExec{ProcessExec: e.process},
			NodeName: nodeName,
			Time:     e.timestamp,
		}
		cache.server.NotifyListeners(e.msg, processedEvent)
	}
	cache.objs = tmp
}

func loop() {
	ticker := time.NewTicker(eventRetryTimer)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			/* Every 'eventRetryTimer' walk the slice of events pending pod info. If
			 * an event hasn't completed its podInfo after two iterations send the
			 * event anyways.
			 */
			handleExecEvents()
			mapmetrics.MapSizeSet("cache", 0, float64(len(cache.objs)))

		case event := <-cache.objsChan:
			errormetrics.EventCacheInc(errormetrics.EventCacheProcessCount)
			cache.objs = append(cache.objs, event)
		}
	}
}

func (ec *Cache) Add(internal *process.ProcessInternal,
	e *tetragon.ProcessExec,
	t *timestamppb.Timestamp,
	msg *processapi.MsgExecveEventUnix) {
	cache.objsChan <- cacheObj{internal: internal, process: e, timestamp: t, msg: msg}
}

func (ec *Cache) Needed(proc *tetragon.Process) bool {
	if proc == nil {
		return true
	}
	if proc.Docker != "" && proc.Pod == nil {
		return true
	}
	return false
}

func New(s *server.Server) *Cache {
	if cache != nil {
		return cache
	}

	cache = &Cache{
		objsChan: make(chan cacheObj),
		objs:     make([]cacheObj, 0),
		server:   s,
	}

	nodeName = node.GetNodeNameForExport()
	go loop()

	return cache
}

func Get() *Cache {
	return cache
}
