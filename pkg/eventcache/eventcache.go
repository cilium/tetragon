// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package eventcache

import (
	"errors"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	kt "github.com/cilium/tetragon/pkg/ktime"
	"github.com/cilium/tetragon/pkg/metrics/errormetrics"
	"github.com/cilium/tetragon/pkg/metrics/eventcachemetrics"
	"github.com/cilium/tetragon/pkg/metrics/mapmetrics"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/cilium/tetragon/pkg/server"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	// garbage collection retries
	CacheStrikes = 15
	// garbage collection run interval
	EventRetryTimer = time.Second * 2
)

var (
	cache    *Cache
	nodeName string
)

type retryFn func(notify.Event, *notify.CacheActions, uint32, uint64) error
type procFn func(*process.ProcessInternal)

type CacheObj struct {
	event     notify.Event
	pid       uint32 // process pid
	ktime     uint64 // process ktime
	timestamp uint64 // event ktime
	color     int
	msg       notify.Message
	actions   *notify.CacheActions
	retry     retryFn
}

type Cache struct {
	objsChan chan CacheObj
	done     chan bool
	cache    []CacheObj
	server   *server.Server
	dur      time.Duration
}

var (
	ErrFailedToGetPodInfo     = errors.New("failed to get pod info")
	ErrFailedToGetProcessInfo = errors.New("failed to get process info")
	ErrFailedToGetParentInfo  = errors.New("failed to get parent info")
)

// We have 2 major caches in Tetragon: (a) processLRU and (b) EventCache.
// (a) processLRU contains mappings from execID to ProcessInternal structures.
//     We add new entries from exec/clone events in the processLRU and we remove
//     them by using reference counting. Exit (and cleanup) events decreases the
//     reference count.
// (b) EventCache is responsible to handle OOO events that miss Process, Parent,
//     or their PodInformation. As handling reference counting is compicated
//     when we have OOO events functions AddProcessParent and AddProcessParentRefInc
//     simplify the interaction with the EventCache.

// AddProcessParent adds process/parent information to the event e. It does not
// affect refcnt. This is ideal for events like kprobe/tracepoint that do not
// come into pairs. This transparently returns the event in the case we don't
// miss anything or adds the event to the EventCache. In that case it uses processLRU
// to get process and parent info.
func AddProcessParent(e notify.Event, msg notify.Message, pid uint32, ktime uint64, timestamp uint64) *tetragon.GetEventsResponse {
	return addProcInfo(e, msg, pid, ktime, timestamp, func(*process.ProcessInternal) {})
}

// The AddProcessParentRef{Inc, Dec} functions do the similar to AddProcessParent
// with the only difference to also increase/decrease the recnt of ProcessInternal.
// These should be used in pairs.
//
// Currently, they are used in exec/clone/exit events. Exec/clone events create a new
// ProcessInternal with refcnt equals to 1 and increases the reference count of the
// parent. Exit events descreases the reference count of the process and parent.
//
// Other examples can be on file events (i.e. increase on file open and decrease on
// file close) or networking events (i.e. increase on connect/accept/listen and
// decrease on close).
func AddProcessParentRefInc(e notify.Event, msg notify.Message, pid uint32, ktime uint64, timestamp uint64) *tetragon.GetEventsResponse {
	return addProcInfo(e, msg, pid, ktime, timestamp, func(p *process.ProcessInternal) { p.RefInc() })
}

func AddProcessParentRefDec(e notify.Event, msg notify.Message, pid uint32, ktime uint64, timestamp uint64) *tetragon.GetEventsResponse {
	return addProcInfo(e, msg, pid, ktime, timestamp, func(p *process.ProcessInternal) { p.RefDec() })
}

func addProcInfo(e notify.Event, msg notify.Message, pid uint32, ktime uint64, timestamp uint64, pFn procFn) *tetragon.GetEventsResponse {
	var tetragonParent, tetragonProcess *tetragon.Process

	proc, parent := process.GetParentProcessInternal(pid, ktime)
	if proc != nil {
		tetragonProcess = proc.GetProcessCopy()
		e.SetProcess(tetragonProcess)
	}
	if parent != nil {
		tetragonParent = parent.GetProcessCopy()
		e.SetParent(tetragonParent)
	}

	act := &notify.CacheActions{
		NeedProcess:    NeededProcess(tetragonProcess),
		NeedProcessPod: NeededPod(tetragonProcess),
		NeedParent:     pid > 1 && NeededProcess(tetragonParent),
		NeedParentPod:  pid > 1 && NeededPod(tetragonParent),
	}

	if !act.NeedProcess {
		pFn(proc)
	}

	if !act.NeedParent {
		pFn(parent)
	}

	if ec := Get(); ec != nil && ec.Needed(act) {
		ec.addWithRetryFn(e, pid, ktime, timestamp, msg, act,
			func(ev notify.Event, ca *notify.CacheActions, pid uint32, ktime uint64) error {
				return GenericRetry(ev, ca, pid, ktime, pFn)
			})
		return nil
	}

	return &tetragon.GetEventsResponse{
		Event:    e.Encapsulate(),
		NodeName: nodeName,
		Time:     kt.ToProto(timestamp),
	}
}

func GenericRetry(ev notify.Event, ca *notify.CacheActions, pid uint32, ktime uint64, pFn procFn) error {
	proc, parent := process.GetParentProcessInternal(pid, ktime)
	var err error

	if ca.NeedProcess {
		if proc == nil {
			errormetrics.ErrorTotalInc(errormetrics.EventCacheProcessInfoFailed)
			err = ErrFailedToGetProcessInfo
		} else {
			pFn(proc)
			ev.SetProcess(proc.GetProcessCopy())
			ca.NeedProcess = false
		}
	}

	if !ca.NeedProcess && ca.NeedProcessPod {
		if proc != nil { // we report errors for that in the previous if no need to do that again
			if option.Config.EnableK8s {
				if p := proc.UnsafeGetProcess(); p.Docker != "" {
					if p.Pod == nil {
						errormetrics.ErrorTotalInc(errormetrics.EventCachePodInfoRetryFailed)
						err = ErrFailedToGetPodInfo
					} else {
						ev.SetProcess(proc.GetProcessCopy())
						ca.NeedProcessPod = false
					}
				}
			}
		}
	}

	if ca.NeedParent {
		if parent == nil {
			errormetrics.ErrorTotalInc(errormetrics.EventCacheParentInfoFailed)
			err = ErrFailedToGetParentInfo
		} else {
			pFn(parent)
			ev.SetParent(parent.GetProcessCopy())
			ca.NeedParent = false
		}
	}

	if !ca.NeedParent && ca.NeedParentPod {
		if parent != nil { // we report errors for that in the previous if no need to do that again
			if option.Config.EnableK8s {
				if p := parent.UnsafeGetProcess(); p.Docker != "" {
					if p.Pod == nil {
						errormetrics.ErrorTotalInc(errormetrics.EventCachePodInfoRetryFailed)
						err = ErrFailedToGetPodInfo
					} else {
						ev.SetParent(parent.GetProcessCopy())
						ca.NeedParentPod = false
					}
				}
			}
		}
	}

	return err
}

func (ec *Cache) handleEvents() {
	tmp := ec.cache[:0]
	for _, event := range ec.cache {

		retryFn := event.retry                          // by default we use GenericRetry
		if c, ok := event.msg.(notify.CacheRetry); ok { // if underlying message implements notify.CacheRetry use that instead
			retryFn = c.Retry
		}

		if err := retryFn(event.event, event.actions, event.pid, event.ktime); err != nil {
			event.color++
			if event.color < CacheStrikes {
				tmp = append(tmp, event)
				continue
			}
			if errors.Is(err, ErrFailedToGetProcessInfo) {
				eventcachemetrics.ProcessInfoError(notify.EventTypeString(event.event)).Inc()
			} else if errors.Is(err, ErrFailedToGetPodInfo) {
				eventcachemetrics.PodInfoError(notify.EventTypeString(event.event)).Inc()
			}
		}

		if event.msg.Notify() {
			// Check if we didn't manage to get the process info and add some basic info.
			// We care for that only when we need to notify.
			if event.event.GetProcess() == nil {
				event.event.SetProcess(&tetragon.Process{
					Pid:       &wrapperspb.UInt32Value{Value: event.pid},
					StartTime: kt.ToProto(event.ktime),
				})
			}

			processedEvent := &tetragon.GetEventsResponse{
				Event:    event.event.Encapsulate(),
				NodeName: nodeName,
				Time:     kt.ToProto(event.timestamp),
			}

			// Do we need to do any further actions after calling
			// NotifyListener? The user can specify a custom action
			// by implementing notify.PostProcessing interface.
			if p, ok := event.msg.(notify.PostProcessing); ok {
				p.PostProcessing(processedEvent)
			}

			ec.server.NotifyListeners(event.msg, processedEvent)
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
			/* Every 'EventRetryTimer' walk the slice of events pending pod info. If
			 * an event hasn't completed its podInfo after two iterations send the
			 * event anyways.
			 */
			ec.handleEvents()
			mapmetrics.MapSizeSet("eventcache", 0, float64(len(ec.cache)))

		case event := <-ec.objsChan:
			eventcachemetrics.EventCacheCount.Inc()
			ec.cache = append(ec.cache, event)

		case <-ec.done:
			return
		}
	}
}

// We handle two race conditions here one where the event races with
// a Tetragon execve event and the other -- much more common -- where we
// race with K8s watcher
func (ec *Cache) Needed(ca *notify.CacheActions) bool {
	return ca.NeedProcess || ca.NeedProcessPod || ca.NeedParent || ca.NeedParentPod
}

// case 1 (execve race):
//  It is possible to receive this Tetragon event before the process event cache
//  has been populated with a Tetragon execve event. In this case we need to
//  cache the event until the process cache is populated.
func NeededProcess(proc *tetragon.Process) bool {
	if proc == nil {
		return true
	}
	if proc.Binary == "" {
		return true
	}
	return false
}

// case 2 (k8s watcher race):
//  It is possible to receive an event before the k8s watcher receives the
//  podInfo event and populates the local cache. If we expect podInfo,
//  indicated by having a nonZero dockerID we cache the event until the
//  podInfo arrives.
func NeededPod(proc *tetragon.Process) bool {
	if option.Config.EnableK8s {
		if proc == nil {
			return true
		}
		if proc.Docker != "" && proc.Pod == nil {
			return true
		}
	}
	return false
}

func (ec *Cache) addWithRetryFn(e notify.Event, pid uint32, ktime uint64, timestamp uint64, msg notify.Message, ca *notify.CacheActions, retry retryFn) {
	co := CacheObj{
		event:     e,
		ktime:     ktime,
		pid:       pid,
		timestamp: timestamp,
		msg:       msg,
		actions:   ca,
		retry:     retry,
	}
	// if we miss process we also don't have docker ID to check
	// for this reason we force NeedProcessPod here
	if option.Config.EnableK8s && ca.NeedProcess {
		ca.NeedProcessPod = true
	}
	if option.Config.EnableK8s && ca.NeedParent {
		ca.NeedParentPod = true
	}
	ec.objsChan <- co
}

func (ec *Cache) Add(e notify.Event, pid uint32, ktime uint64, timestamp uint64, msg notify.Message, ca *notify.CacheActions) {
	ec.addWithRetryFn(e, pid, ktime, timestamp, msg, ca, nil)
}

func NewWithTimer(s *server.Server, dur time.Duration) *Cache {
	if cache != nil {
		cache.done <- true
	}

	cache = &Cache{
		objsChan: make(chan CacheObj),
		done:     make(chan bool),
		cache:    make([]CacheObj, 0),
		server:   s,
		dur:      dur,
	}
	nodeName = node.GetNodeNameForExport()
	go cache.loop()
	return cache
}

func New(s *server.Server) *Cache {
	return NewWithTimer(s, EventRetryTimer)
}

func Get() *Cache {
	return cache
}
