// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package eventcache

import (
	"errors"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/cilium/tetragon/pkg/server"
)

const (
	// Event information was completed without cache retries
	NO_EV_CACHE = iota
	// Cache retries was triggered in order to complete event information
	FROM_EV_CACHE
)

var (
	cache *Cache
)

type CacheObj struct {
	internal  *process.ProcessInternal
	event     notify.Event
	timestamp uint64
	startTime uint64
	color     int
	msg       notify.Message
}

type Cache struct {
	objsChan chan CacheObj
	done     chan bool
	cache    []CacheObj
	notifier server.Notifier
	dur      time.Duration
}

var (
	ErrFailedToGetPodInfo       = errors.New("failed to get pod info from event cache")
	ErrFailedToGetProcessInfo   = errors.New("failed to get process info from event cache")
	ErrFailedToGetParentInfo    = errors.New("failed to get parent info from event cache")
	ErrFailedToGetAncestorsInfo = errors.New("failed to get ancestors info from event cache")
)

func enabledAncestors(ev notify.Event) bool {
	switch ev.(type) {
	case *tetragon.ProcessKprobe:
		return option.Config.EnableProcessKprobeAncestors
	case *tetragon.ProcessTracepoint:
		return option.Config.EnableProcessTracepointAncestors
	case *tetragon.ProcessUprobe:
		return option.Config.EnableProcessUprobeAncestors
	case *tetragon.ProcessLsm:
		return option.Config.EnableProcessLsmAncestors
	default:
		return false
	}
}

// Generic internal lookup happens when events are received out of order and
// this event was handled before an exec event so it wasn't able to populate
// the process info yet.
func HandleGenericInternal(ev notify.Event, pid uint32, tid *uint32, timestamp uint64) (*process.ProcessInternal, error) {
	internal, parent := process.GetParentProcessInternal(pid, timestamp)
	var err error

	if enabledAncestors(ev) && internal.NeededAncestors() {
		// We do not need to try to recollect all ancestors starting from the immediate parent here,
		// if we already collected some of them in previous attempts. So, if we already have a number
		// of ancestors collected, we just need to try to resume the collection process from the last
		// known ancestor.
		tetragonAncestors := ev.GetAncestors()
		var nextExecId string

		if len(tetragonAncestors) == 0 {
			nextExecId = internal.UnsafeGetProcess().ParentExecId
		} else {
			nextExecId = tetragonAncestors[len(tetragonAncestors)-1].ExecId
		}

		if ancestors, perr := process.GetAncestorProcessesInternal(nextExecId); perr == nil {
			for _, ancestor := range ancestors {
				tetragonAncestors = append(tetragonAncestors, ancestor.UnsafeGetProcess())
			}
			ev.SetAncestors(tetragonAncestors)
		} else {
			CacheRetries(AncestorsInfo).Inc()
			err = ErrFailedToGetAncestorsInfo
		}
	}

	if parent != nil {
		ev.SetParent(parent.UnsafeGetProcess())
	} else {
		CacheRetries(ParentInfo).Inc()
		err = ErrFailedToGetParentInfo
	}

	if internal != nil {
		// When we report the per thread fields, take a copy
		// of the thread leader from the cache then update the corresponding
		// per thread fields.
		//
		// The cost to get this is relatively high because it requires a
		// deep copy of all the fields of the thread leader from the cache in
		// order to safely modify them, to not corrupt gRPC streams.
		proc := internal.GetProcessCopy()
		process.UpdateEventProcessTid(proc, tid)
		ev.SetProcess(proc)
	} else {
		CacheRetries(ProcessInfo).Inc()
		err = ErrFailedToGetProcessInfo
	}

	if err == nil {
		return internal, err
	}
	return nil, err
}

// Generic Event handler without any extra msg specific details or debugging
// so we only need to wait for the internal link to the process context to
// resolve PodInfo. This happens when the msg populates the internal state
// but that event is not fully populated yet.
func HandleGenericEvent(internal *process.ProcessInternal, ev notify.Event, tid *uint32) error {
	p := internal.UnsafeGetProcess()
	if option.Config.EnableK8s && p.Pod == nil {
		CacheRetries(PodInfo).Inc()
		return ErrFailedToGetPodInfo
	}

	// When we report the per thread fields, take a copy
	// of the thread leader from the cache then update the corresponding
	// per thread fields.
	//
	// The cost to get this is relatively high because it requires a
	// deep copy of all the fields of the thread leader from the cache in
	// order to safely modify them, to not corrupt gRPC streams.
	proc := internal.GetProcessCopy()
	process.UpdateEventProcessTid(proc, tid)
	ev.SetProcess(proc)
	return nil
}

func (ec *Cache) handleEvents() {
	tmp := ec.cache[:0]
	for _, event := range ec.cache {
		var err error

		// If the process wasn't found before the Add(), likely because
		// the execve event was processed after this event, lets look it up
		// now because it should be available. Otherwise we have a valid
		// process and lets copy it across.
		if event.internal == nil {
			event.internal, err = event.msg.RetryInternal(event.event, event.startTime)
		}
		if err == nil {
			err = event.msg.Retry(event.internal, event.event)
		}
		if err != nil {
			event.color++
			if event.color < option.Config.EventCacheNumRetries {
				tmp = append(tmp, event)
				continue
			}
			eventType := notify.EventType(event.event).String()
			if errors.Is(err, ErrFailedToGetParentInfo) {
				failedFetches.WithLabelValues(eventType, ParentInfo.String()).Inc()
			} else if errors.Is(err, ErrFailedToGetProcessInfo) {
				failedFetches.WithLabelValues(eventType, ProcessInfo.String()).Inc()
			} else if errors.Is(err, ErrFailedToGetAncestorsInfo) {
				failedFetches.WithLabelValues(eventType, AncestorsInfo.String()).Inc()
			} else if errors.Is(err, ErrFailedToGetPodInfo) {
				failedFetches.WithLabelValues(eventType, PodInfo.String()).Inc()
			}
		}

		if event.msg.Notify() {
			processedEvent := &tetragon.GetEventsResponse{
				Event: event.event.Encapsulate(),
				Time:  ktime.ToProto(event.timestamp),
			}

			ec.notifier.NotifyListener(event.msg, processedEvent)
		}
	}
	ec.cache = tmp
}

func (ec *Cache) loop() {
	ticker := time.NewTicker(ec.dur)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			/* Every 'option.Config.EventCacheRetryDelay' seconds walk the slice of events
			 * pending pod info. If an event hasn't completed its podInfo after two iterations
			 * send the event anyways.
			 */
			ec.handleEvents()

		case event := <-ec.objsChan:
			cacheInserts.Inc()
			ec.cache = append(ec.cache, event)

		case <-ec.done:
			return
		}
	}
}

// We handle two race conditions here one where the event races with
// a Tetragon execve event and the other -- much more common -- where we
// race with K8s watcher
// case 1 (execve race):
//
//	Its possible to receive this Tetragon event before the process event cache
//	has been populated with a Tetragon execve event. In this case we need to
//	cache the event until the process cache is populated.
//
// case 2 (k8s watcher race):
//
//	Its possible to receive an event before the k8s watcher receives the
//	podInfo event and populates the local cache. If we expect podInfo,
//	indicated by having a nonZero dockerID we cache the event until the
//	podInfo arrives.
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

func (ec *Cache) NeededAncestors(parent *process.ProcessInternal, ancestors []*process.ProcessInternal) bool {
	if parent.NeededAncestors() {
		if len(ancestors) == 0 {
			return true
		}
		if ancestors[len(ancestors)-1].UnsafeGetProcess().Pid.Value > 2 {
			return true
		}
	}
	return false
}

func (ec *Cache) Add(internal *process.ProcessInternal,
	e notify.Event,
	t uint64,
	s uint64,
	msg notify.Message) {
	ec.objsChan <- CacheObj{internal: internal, event: e, timestamp: t, startTime: s, msg: msg}
}

func NewWithTimer(n server.Notifier, dur time.Duration) *Cache {
	if cache != nil {
		cache.done <- true
	}

	logger.GetLogger().WithField("retries", option.Config.EventCacheNumRetries).WithField("delay", dur).Info("Creating new EventCache")

	cache = &Cache{
		objsChan: make(chan CacheObj),
		done:     make(chan bool),
		cache:    make([]CacheObj, 0),
		notifier: n,
		dur:      dur,
	}
	go cache.loop()
	return cache
}

func New(n server.Notifier) *Cache {
	return NewWithTimer(n, time.Second*time.Duration(option.Config.EventCacheRetryDelay))
}

func Get() *Cache {
	return cache
}

func (ec *Cache) len() int {
	return len(ec.cache)
}
