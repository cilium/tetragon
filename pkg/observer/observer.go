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
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/tetragon/pkg/api/readyapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics/errormetrics"
	"github.com/cilium/tetragon/pkg/metrics/opcodemetrics"
	"github.com/cilium/tetragon/pkg/metrics/ringbufmetrics"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/config/confmap"

	"github.com/sirupsen/logrus"
)

const (
	perCPUBufferBytes = 65535
)

var (
	eventHandler = make(map[uint8]func(r *bytes.Reader) ([]Event, error))

	observerList []*Observer

	/* SensorManager handles dynamic sensors loading / unloading. */
	SensorManager *sensors.Manager
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

type handlePerfUnknownOp struct {
	op byte
}

func (e handlePerfUnknownOp) Error() string {
	return fmt.Sprintf("unknown op: %d", e.op)
}

type handlePerfHandlerErr struct {
	op  byte
	err error
}

func (e *handlePerfHandlerErr) Error() string {
	return fmt.Sprintf("handler for op %d failed: %s", e.op, e.err)
}

func (e *handlePerfHandlerErr) Unwrap() error {
	return e.err
}

func (e *handlePerfHandlerErr) Cause() error {
	return e.err
}

// HandlePerfData returns the events from raw bytes
// NB: It is made public so that it can be used in testing.
func HandlePerfData(data []byte) (byte, []Event, error) {
	op := data[0]
	r := bytes.NewReader(data)
	// These ops handlers are registered by RegisterEventHandlerAtInit().
	handler, ok := eventHandler[op]
	if !ok {
		return op, nil, handlePerfUnknownOp{op: op}
	}

	events, err := handler(r)
	if err != nil {
		err = &handlePerfHandlerErr{op: op, err: err}
	}
	return op, events, err
}

func (k *Observer) receiveEvent(data []byte) {
	atomic.AddUint64(&k.recvCntr, 1)
	op, events, err := HandlePerfData(data)
	opcodemetrics.OpTotalInc(int(op))
	if err != nil {
		// Increment error metrics
		errormetrics.ErrorTotalInc(errormetrics.HandlerError)
		errormetrics.HandlerErrorsInc(int(op), err)
		switch e := err.(type) {
		case handlePerfUnknownOp:
			k.log.WithField("opcode", e.op).Debug("unknown opcode ignored")
		case *handlePerfHandlerErr:
			k.log.WithError(e.err).WithField("opcode", e.op).Debug("error occurred in event handler")
		default:
			k.log.WithError(err).Debug("error occurred in event handler")
		}
	}
	for _, event := range events {
		k.observerListeners(event)
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

	k.log.WithField("percpu", cpuSize).WithField("total", totalSize).Info("Perf ring buffer size (bytes)")
	return size
}

func (k *Observer) runEvents(stopCtx context.Context, ready func()) error {
	pinOpts := ebpf.LoadPinOptions{}
	perfMap, err := ebpf.LoadPinnedMap(k.perfConfig.MapName, &pinOpts)
	if err != nil {
		return fmt.Errorf("opening pinned map '%s' failed: %w", k.perfConfig.MapName, err)
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
					errorCnt := atomic.AddUint64(&k.errorCntr, 1)
					ringbufmetrics.ErrorsSet(float64(errorCnt))
					k.log.WithField("errors", errorCnt).WithError(err).Warn("Reading bpf events failed")
				}
			} else {
				if len(record.RawSample) > 0 {
					k.receiveEvent(record.RawSample)
					ringbufmetrics.ReceivedSet(float64(k.ReadReceivedEvents()))
				}

				if record.LostSamples > 0 {
					lostCnt := atomic.AddUint64(&k.lostCntr, uint64(record.LostSamples))
					ringbufmetrics.LostSet(float64(lostCnt))
				}
			}
		}
		k.log.WithError(stopCtx.Err()).Info("Listening for events completed.")
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
	perfConfig *bpf.PerfEventConfig
	/* Statistics */
	lostCntr   uint64 // atomic
	errorCntr  uint64 // atomic
	recvCntr   uint64 // atomic
	filterPass uint64
	filterDrop uint64
	/* Filters */
	log logrus.FieldLogger

	/* YAML Configuration File */
	configFile string
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
func (k *Observer) UpdateRuntimeConf(mapDir string) error {
	pid := os.Getpid()
	err := confmap.UpdateTgRuntimeConf(mapDir, pid)
	if err != nil {
		k.log.WithField("observer", "confmap-update").WithError(err).Warn("Update TetragonConf map failed, advanced Cgroups tracking will be disabled")
		k.log.WithField("observer", "confmap-update").Warn("Continuing without advanced Cgroups tracking. Process association with Pods and Containers might be limited")
	}

	return err
}

// Start starts the observer
func (k *Observer) Start(ctx context.Context) error {
	k.startUpdateMapMetrics()

	k.perfConfig = bpf.DefaultPerfEventConfig()

	var err error
	if err = k.runEvents(ctx, func() {}); err != nil {
		return fmt.Errorf("tetragon, aborting runtime error: %w", err)
	}
	return nil
}

// InitSensorManager starts the sensor controller
func (k *Observer) InitSensorManager(waitChan chan struct{}) error {
	var err error
	SensorManager, err = sensors.StartSensorManager(option.Config.BpfDir, option.Config.MapDir, option.Config.CiliumDir, waitChan)
	return err
}

func NewObserver(configFile string) *Observer {
	o := &Observer{
		listeners:  make(map[Listener]struct{}),
		log:        logger.GetLogger(),
		configFile: configFile,
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
	return atomic.LoadUint64(&k.lostCntr)
}

func (k *Observer) ReadErrorEvents() uint64 {
	return atomic.LoadUint64(&k.errorCntr)
}

func (k *Observer) ReadReceivedEvents() uint64 {
	return atomic.LoadUint64(&k.recvCntr)
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

func (k *Observer) RemovePrograms() {
	RemovePrograms(option.Config.BpfDir, option.Config.MapDir)
}

// Log Active pinned BPF resources
func (k *Observer) LogPinnedBpf(observerDir string) {
	finfo, err := os.Stat(observerDir)
	if err != nil {
		k.log.WithField("bpf-dir", observerDir).Info("BPF: resources are empty")
		return
	}

	if finfo.IsDir() == false {
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
