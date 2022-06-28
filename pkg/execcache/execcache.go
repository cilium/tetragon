// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package execcache

import (
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/dns"
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
	cache    []cacheObj
	dns      *dns.Cache
	server   *server.Server
}

func (ec *Cache) handleExecEvents() {
	tmp := ec.cache[:0]
	for _, e := range ec.cache {
		containerId := e.process.Process.Docker
		filename := e.process.Process.Binary
		args := string(e.process.Process.Args)
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
			ec.handleExecEvents()
			mapmetrics.MapSizeSet("cache", 0, float64(len(ec.cache)))

		case event := <-ec.objsChan:
			errormetrics.EventCacheInc(errormetrics.EventCacheProcessCount)
			ec.cache = append(ec.cache, event)
		}
	}
}

func (ec *Cache) Add(internal *process.ProcessInternal,
	e *tetragon.ProcessExec,
	t *timestamppb.Timestamp,
	msg *processapi.MsgExecveEventUnix) {
	ec.objsChan <- cacheObj{internal: internal, process: e, timestamp: t, msg: msg}
}

func New(s *server.Server, dns *dns.Cache) *Cache {
	ec := &Cache{
		objsChan: make(chan cacheObj),
		cache:    make([]cacheObj, 0),
		dns:      dns,
		server:   s,
	}
	nodeName = node.GetNodeNameForExport()
	go ec.loop()
	return ec
}
