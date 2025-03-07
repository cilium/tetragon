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

	// Use a sync.Pool to reuse bytes.Reader objects
	readerPool = sync.Pool{
		New: func() interface{} {
			return new(bytes.Reader)
		},
	}
)

// Event is defined the same as notify.Message
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

// HandlePerfError wraps errors from perf data handling
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

// HandlePerfData uses the object pool to get a bytes.Reader for parsing perf data
func HandlePerfData(data []byte) (byte, []Event, *HandlePerfError) {
	op := data[0]
	r := readerPool.Get().(*bytes.Reader)
	defer readerPool.Put(r)
	r.Reset(data)
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

// perfBufferSize calculates the final ring buffer size based on the perCPUBuffer parameter
func perfBufferSize(perCPUBuffer int) int {
	pageSize := os.Getpagesize()
	nPages := (perCPUBuffer + pageSize - 1) / pageSize
	nPages = int(math.Pow(2, math.Ceil(math.Log2(float64(nPages)))))
	nPages++
	return nPages * pageSize
}

func sizeWithSuffix(size int) string {
	suffix := [4]string{"", "K", "M", "G"}
	i := 0
	for size > 1024 && i < 3 {
		size = size / 1024
		i++
	}
	return fmt.Sprintf("%d%s", size, suffix[i])
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
	k.log.WithField("percpu", sizeWithSuffix(cpuSize)).
		WithField("total", sizeWithSuffix(totalSize)).
		Info("Perf ring buffer size (bytes)")
	return size
}

func (k *Observer) getRBQueueSize() int {
	size := option.Config.RBQueueSize
	if size == 0 {
		size = 65535
	}
	k.log.WithField("size", sizeWithSuffix(size)).
		Info("Perf ring buffer events queue size (events)")
	return size
}

// RunEvents uses a batched reading and processing strategy for perf events to improve memory and CPU utilization
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

	// Notify listeners that event processing is about to start
	k.observerListeners(&readyapi.MsgTetragonReady{})
	ready()

	// Use a larger queue capacity to reduce channel contention
	queueSize := runtime.NumCPU() * 1024
	eventsQueue := make(chan *perf.Record, queueSize)

	k.log.Info("Listening for events...")

	var wg sync.WaitGroup

	// Batch read perf events and push them into the event queue
	wg.Add(1)
	go func() {
		defer wg.Done()
		batch := make([]*perf.Record, 0, 100)
		for stopCtx.Err() == nil {
			record, err := perfReader.Read()
			if err != nil {
				if stopCtx.Err() == nil {
					RingbufErrors.Inc()
					errorCnt := getCounterValue(RingbufErrors)
					k.log.WithField("errors", errorCnt).WithError(err).Warn("Reading bpf events failed")
				}
				continue
			}
			if len(record.RawSample) > 0 {
				batch = append(batch, &record)
				RingbufReceived.Inc()
			}
			if record.LostSamples > 0 {
				RingbufLost.Add(float64(record.LostSamples))
			}
			// When the batch size is reached, send the entire batch to the event queue
			if len(batch) >= 128 {
				for _, rec := range batch {
					eventsQueue <- rec
				}
				batch = batch[:0]
			}
		}
		// Process any remaining records that did not fill the batch
		if len(batch) > 0 {
			for _, rec := range batch {
				eventsQueue <- rec
			}
		}
	}()

	// Process events from the event queue and trigger GC periodically after processing a certain number of events
	wg.Add(1)
	go func() {
		defer wg.Done()
		processedEvents := 0
		for {
			select {
			case event := <-eventsQueue:
				k.receiveEvent(event.RawSample)
				processedEvents++
				if processedEvents%500 == 0 {
					runtime.GC()
				}
			case <-stopCtx.Done():
				k.log.WithError(stopCtx.Err()).Info("Listening for events completed.")
				k.log.Debugf("Unprocessed events in RB queue: %d", len(eventsQueue))
				return
			}
		}
	}()

	<-stopCtx.Done()
	wg.Wait()
	return perfReader.Close()
}

// Observer represents the bridge between the BPF perf ring and event listeners, managing the perf ring and event distribution.
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
	/* Logger */
	log logrus.FieldLogger
}

// UpdateRuntimeConf updates the runtime configuration
func (k *Observer) UpdateRuntimeConf(bpfDir string) error {
	pid := os.Getpid()
	err := confmap.UpdateTgRuntimeConf(bpfDir, pid)
	if err != nil {
		k.log.WithField("observer", "confmap-update").WithError(err).Warn("Update TetragonConf map failed, advanced Cgroups tracking will be disabled")
		k.log.WithField("observer", "confmap-update").Warn("Continuing without advanced Cgroups tracking. Process association with Pods and Containers might be limited")
	}
	return err
}

// Start starts the observer using StartReady
func (k *Observer) Start(ctx context.Context) error {
	return k.StartReady(ctx, func() {})
}

// StartReady starts the observer and calls the ready callback
func (k *Observer) StartReady(ctx context.Context, ready func()) error {
	k.PerfConfig = bpf.DefaultPerfEventConfig()
	if err := k.RunEvents(ctx, ready); err != nil {
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

// LogPinnedBpf logs the active pinned BPF resources
func (k *Observer) LogPinnedBpf(observerDir string) {
	finfo, err := os.Stat(observerDir)
	if err != nil {
		k.log.WithField("bpf-dir", observerDir).Info("BPF: resources are empty")
		return
	}
	if !finfo.IsDir() {
		err := fmt.Errorf("is not a directory")
		k.log.WithField("bpf-dir", observerDir).WithError(err).Warn("BPF: checking BPF resources failed")
		return
	}
	bpfRes, _ := os.ReadDir(observerDir)
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