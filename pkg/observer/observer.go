// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package observer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/metrics/errormetrics"
	"github.com/cilium/tetragon/pkg/metrics/opcodemetrics"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/config/confmap"
	"github.com/cilium/tetragon/pkg/strutils"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
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
	k.log.Debug("Add listener", "listener", listener)
	k.listeners[listener] = struct{}{}
}

func (k *Observer) RemoveListener(listener Listener) {
	k.log.Debug("Delete listener", "listener", listener)
	delete(k.listeners, listener)
	if err := listener.Close(); err != nil {
		k.log.Warn("failed to close listener", logfields.Error, err)
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
			k.log.Debug("unknown opcode ignored", "opcode", err.opcode)
		default:
			k.log.Debug("error occurred in event handler", "opcode", err.opcode, logfields.Error, err)
		}
	}
	for _, event := range events {
		k.observerListeners(event)
	}
	if option.Config.EnableMsgHandlingLatency {
		opcodemetrics.LatencyStats.WithLabelValues(strconv.FormatUint(uint64(op), 10)).Observe(float64(time.Since(timer).Microseconds()))
	}
}

func (k *Observer) getRBQueueSize() int {
	size := option.Config.RBQueueSize
	if size == 0 {
		size = 65535
	}
	k.log.Info("Perf ring buffer events queue size (events)", "size", strutils.SizeWithSuffix(size))
	return size
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
	log logger.FieldLogger
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
		k.log.Warn("Update TetragonConf map failed, advanced Cgroups tracking will be disabled", "observer", "confmap-update", logfields.Error, err)
		k.log.Warn("Continuing without advanced Cgroups tracking. Process association with Pods and Containers might be limited", "observer", "confmap-update")
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
	k.log.Info(fmt.Sprintf("BPF events statistics: %d received, %.2g%% events loss", recvCntr, loss))

	k.log.Info("Observer events statistics",
		"received", recvCntr,
		"lost", lostCntr,
		"errors", k.ReadErrorEvents(),
		"filterPass", k.filterPass,
		"filterDrop", k.filterDrop)
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
		k.log.Info("BPF: resources are empty", "bpf-dir", observerDir)
		return
	}

	if !finfo.IsDir() {
		err := errors.New("is not a directory")
		k.log.Warn("BPF: checking BPF resources failed", "bpf-dir", observerDir, logfields.Error, err)
		// Do not fail, let bpf part handle it
		return
	}

	bpfRes, _ := os.ReadDir(observerDir)
	// Do not fail, let bpf part handle it
	if len(bpfRes) == 0 {
		k.log.Info("BPF: resources are empty", "bpf-dir", observerDir)
	} else {
		res := make([]string, 0)
		for _, b := range bpfRes {
			res = append(res, b.Name())
		}
		k.log.Info("BPF: found active BPF resources", "bpf-dir", observerDir,
			"pinned-bpf", fmt.Sprintf("[%s]", strings.Join(res, " ")))
	}
}

func getCounterValue(counter prometheus.Counter) uint64 {
	var d dto.Metric
	counter.Write(&d)
	return uint64(*d.Counter.Value)
}
