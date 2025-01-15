// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package observer

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/api/readyapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics/errormetrics"
	"github.com/cilium/tetragon/pkg/metrics/opcodemetrics"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/config/confmap"
	"github.com/cilium/tetragon/pkg/strutils"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/sirupsen/logrus"
)

const (
	perCPUBufferBytes = 65535
)

var (
	eventHandler = make(map[uint8]func(r *bytes.Reader) ([]Event, error))

	observerList []*Observer
)

type Event notify.Message

func RegisterEventHandlerAtInit(ev uint8, handler func(r *bytes.Reader) ([]Event, error)) {
	eventHandler[ev] = handler
}

func (k *Observer) observerListeners(msg notify.Message) {
	for listener := range k.listeners {
		if err := listener.Notify(msg); err != nil {
			k.log.Debug("Write failure removing Listener")
			k.RemoveListener(listener)
		}
	}
}

func AllListeners(msg notify.Message) {
	for _, o := range observerList {
		o.observerListeners(msg)
	}
}

func (k *Observer) AddListener(listener Listener) {
	k.log.WithField("listener", listener).Debug("Add listener")
	k.listeners[listener] = struct{}{}
}

func (k *Observer) RemoveListener(listener Listener) {
	k.log.WithField("listener", listener).Debug("Delete listener")
	delete(k.listeners, listener)
	if err := listener.Close(); err != nil {
		k.log.WithError(err).Warn("failed to close listener")
	}
}

type HandlePerfError struct {
	kind   errormetrics.EventHandlerError
	err    error
	opcode byte
}

func (e *HandlePerfError) Error() string {
	return e.err.Error()
}

func (e *HandlePerfError) Unwrap() error {
	return e.err
}

// HandlePerfData returns the events from raw bytes
// NB: It is made public so that it can be used in testing.
func HandlePerfData(data []byte) (byte, []Event, *HandlePerfError) {
	op := data[0]
	r := bytes.NewReader(data)
	// These ops handlers are registered by RegisterEventHandlerAtInit().
	handler, ok := eventHandler[op]
	if !ok {
		return op, nil, &HandlePerfError{
			kind:   errormetrics.HandlePerfUnknownOp,
			err:    fmt.Errorf("unknown op: %d", op),
			opcode: op,
		}
	}

	events, err := handler(r)
	if err != nil {
		return op, events, &HandlePerfError{
			kind:   errormetrics.HandlePerfHandlerError,
			err:    fmt.Errorf("handler for op %d failed: %w", op, err),
			opcode: op,
		}
	}
	return op, events, nil
}

func (k *Observer) receiveEvent(data []byte) {
	var timer time.Time
	if option.Config.EnableMsgHandlingLatency {
		timer = time.Now()
	}

	op, events, err := HandlePerfData(data)
	opcodemetrics.OpTotalInc(ops.OpCode(op))
	if err != nil {
		errormetrics.HandlerErrorsInc(ops.OpCode(op), err.kind)
		switch err.kind {
		case errormetrics.HandlePerfUnknownOp:
			k.log.WithField("opcode", err.opcode).Debug("unknown opcode ignored")
		default:
			k.log.WithError(err).WithField("opcode", err.opcode).Debug("error occurred in event handler")
		}
	}
	for _, event := range events {
		k.observerListeners(event)
	}
	if option.Config.EnableMsgHandlingLatency {
		opcodemetrics.LatencyStats.WithLabelValues(fmt.Sprint(op)).Observe(float64(time.Since(timer).Microseconds()))
	}
}

// Gets final size for single perf ring buffer rounded from
// passed size argument (kindly borrowed from ebpf/cilium)
func perfBufferSize(perCPUBuffer int) int {
	pageSize := os.Getpagesize()

	// Smallest whole number of pages
	nPages := (perCPUBuffer + pageSize - 1) / pageSize

	// Round up to nearest power of two number of pages
	nPages = int(math.Pow(2, math.Ceil(math.Log2(float64(nPages)))))

	// Add one for metadata
	nPages++

	return nPages * pageSize
}

func (k *Observer) getRBSize(cpus int) int {
	var size int

	if option.Config.RBSize == 0 && option.Config.RBSizeTotal == 0 {
		size = perCPUBufferBytes
	} else if option.Config.RBSize != 0 {
		size = option.Config.RBSize
	} else {
		size = option.Config.RBSizeTotal / int(cpus)
	}

	cpuSize := perfBufferSize(size)
	totalSize := cpuSize * cpus

	k.log.WithField("percpu", strutils.SizeWithSuffix(cpuSize)).
		WithField("total", strutils.SizeWithSuffix(totalSize)).
		Info("Perf ring buffer size (bytes)")
	return size
}

func (k *Observer) getRBQueueSize() int {
	size := option.Config.RBQueueSize
	if size == 0 {
		size = 65535
	}
	k.log.WithField("size", strutils.SizeWithSuffix(size)).
		Info("Perf ring buffer events queue size (events)")
	return size
}

func (k *Observer) RunEvents(stopCtx context.Context, ready func()) error {
	pinOpts := ebpf.LoadPinOptions{}
	perfMap, err := ebpf.LoadPinnedMap(k.PerfConfig.MapName, &pinOpts)
	if err != nil {
		return fmt.Errorf("opening pinned map '%s' failed: %w", k.PerfConfig.MapName, err)
	}
	defer perfMap.Close()

	rbSize := k.getRBSize(int(perfMap.MaxEntries()))
	perfReader, err := perf.NewReader(perfMap, rbSize)

	if err != nil {
		return fmt.Errorf("creating perf array reader failed: %w", err)
	}

	// Inform caller that we're about to start processing events.
	k.observerListeners(&readyapi.MsgTetragonReady{})
	ready()

	// We spawn go routine to read and process perf events,
	// connected with main app through eventsQueue channel.
	eventsQueue := make(chan *perf.Record, k.getRBQueueSize())

	// Listeners are ready and about to start reading from perf reader, tell
	// user everything is ready.
	k.log.Info("Listening for events...")

	// Start reading records from the perf array. Reads until the reader is closed.
	var wg sync.WaitGroup
	wg.Add(1)
	defer wg.Wait()
	go func() {
		defer wg.Done()
		for stopCtx.Err() == nil {
			record, err := perfReader.Read()
			if err != nil {
				// NOTE(JM and Djalal): count and log errors while excluding the stopping context
				if stopCtx.Err() == nil {
					RingbufErrors.Inc()
					errorCnt := getCounterValue(RingbufErrors)
					k.log.WithField("errors", errorCnt).WithError(err).Warn("Reading bpf events failed")
				}
			} else {
				if len(record.RawSample) > 0 {
					select {
					case eventsQueue <- &record:
					default:
						// eventsQueue channel is full, drop the event
						queueLost.Inc()
					}
					RingbufReceived.Inc()
				}

				if record.LostSamples > 0 {
					RingbufLost.Add(float64(record.LostSamples))
				}
			}
		}
	}()

	// Start processing records from perf.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case event := <-eventsQueue:
				k.receiveEvent(event.RawSample)
				queueReceived.Inc()
			case <-stopCtx.Done():
				k.log.WithError(stopCtx.Err()).Infof("Listening for events completed.")
				k.log.Debugf("Unprocessed events in RB queue: %d", len(eventsQueue))
				return
			}
		}
	}()

	// Loading default program consumes some memory lets kick GC to give
	// this back to the OS (K8s).
	go func() {
		runtime.GC()
	}()

	// Wait for context to be cancelled and then stop.
	<-stopCtx.Done()
	return perfReader.Close()
}

// Observer represents the link between the BPF perf ring and the listeners. It
// manages the perf ring and receive events from it. It ensures that the BPF
// event we are receiving from the kernel is complete. The listeners are
// notified of their corresponding events.
type Observer struct {
	/* Configuration */
	listeners  map[Listener]struct{}
	PerfConfig *bpf.PerfEventConfig
	/* Statistics */
	lostCntr   prometheus.Counter
	errorCntr  prometheus.Counter
	recvCntr   prometheus.Counter
	filterPass uint64
	filterDrop uint64
	/* Filters */
	log logrus.FieldLogger
}

// UpdateRuntimeConf() Gathers information about Tetragon runtime environment and
// updates BPF map TetragonConfMap
//
// The observer needs to do this to discover and properly operate on the right
// cgroup context. Use this function in your tests to allow Pod and Containers
// association to work.
//
// The environment and cgroup configuration discovery may fail for several
// reasons, in such cases errors will be logged.
// On errors we also print a warning that advanced Cgroups tracking will be
// disabled which might affect process association with kubernetes pods and
// containers.
func (k *Observer) UpdateRuntimeConf(bpfDir string) error {
	pid := os.Getpid()
	err := confmap.UpdateTgRuntimeConf(bpfDir, pid)
	if err != nil {
		k.log.WithField("observer", "confmap-update").WithError(err).Warn("Update TetragonConf map failed, advanced Cgroups tracking will be disabled")
		k.log.WithField("observer", "confmap-update").Warn("Continuing without advanced Cgroups tracking. Process association with Pods and Containers might be limited")
	}

	return err
}

// Start starts the observer
func (k *Observer) Start(ctx context.Context) error {
	return k.StartReady(ctx, func() {})
}

func (k *Observer) StartReady(ctx context.Context, ready func()) error {
	k.PerfConfig = bpf.DefaultPerfEventConfig()

	var err error
	if err = k.RunEvents(ctx, ready); err != nil {
		return fmt.Errorf("tetragon, aborting runtime error: %w", err)
	}
	return nil
}

// InitSensorManager starts the sensor controller
func (k *Observer) InitSensorManager() error {
	mgr, err := sensors.StartSensorManager(option.Config.BpfDir)
	if err != nil {
		return err
	}
	return SetSensorManager(mgr)
}

func NewObserver() *Observer {
	o := &Observer{
		listeners: make(map[Listener]struct{}),
		lostCntr:  RingbufLost,
		errorCntr: RingbufErrors,
		recvCntr:  RingbufReceived,
		log:       logger.GetLogger(),
	}
	observerList = append(observerList, o)
	return o
}

func (k *Observer) Remove() {
	for i, obs := range observerList {
		if obs == k {
			observerList = append(observerList[:i], observerList[i+1:]...)
			break
		}
	}
}

func (k *Observer) ReadLostEvents() uint64 {
	return getCounterValue(k.lostCntr)
}

func (k *Observer) ReadErrorEvents() uint64 {
	return getCounterValue(k.errorCntr)
}

func (k *Observer) ReadReceivedEvents() uint64 {
	return getCounterValue(k.recvCntr)
}

func (k *Observer) PrintStats() {
	recvCntr := k.ReadReceivedEvents()
	lostCntr := k.ReadLostEvents()
	total := float64(recvCntr + lostCntr)
	loss := float64(0)
	if total > 0 {
		loss = (float64(lostCntr) * 100.0) / total
	}
	k.log.Infof("BPF events statistics: %d received, %.2g%% events loss", recvCntr, loss)

	k.log.WithFields(logrus.Fields{
		"received":   recvCntr,
		"lost":       lostCntr,
		"errors":     k.ReadErrorEvents(),
		"filterPass": k.filterPass,
		"filterDrop": k.filterDrop,
	}).Info("Observer events statistics")
}

func RemoveSensors(ctx context.Context) {
	if mgr := GetSensorManager(); mgr != nil {
		mgr.RemoveAllSensors(ctx)
	}
}

// Log Active pinned BPF resources
func (k *Observer) LogPinnedBpf(observerDir string) {
	finfo, err := os.Stat(observerDir)
	if err != nil {
		k.log.WithField("bpf-dir", observerDir).Info("BPF: resources are empty")
		return
	}

	if !finfo.IsDir() {
		err := fmt.Errorf("is not a directory")
		k.log.WithField("bpf-dir", observerDir).WithError(err).Warn("BPF: checking BPF resources failed")
		// Do not fail, let bpf part handle it
		return
	}

	bpfRes, _ := os.ReadDir(observerDir)
	// Do not fail, let bpf part handle it
	if len(bpfRes) == 0 {
		k.log.WithField("bpf-dir", observerDir).Info("BPF: resources are empty")
	} else {
		res := make([]string, 0)
		for _, b := range bpfRes {
			res = append(res, b.Name())
		}
		k.log.WithFields(logrus.Fields{
			"bpf-dir":    observerDir,
			"pinned-bpf": fmt.Sprintf("[%s]", strings.Join(res, " ")),
		}).Info("BPF: found active BPF resources")
	}
}

func getCounterValue(counter prometheus.Counter) uint64 {
	var d dto.Metric
	counter.Write(&d)
	return uint64(*d.Counter.Value)
}
