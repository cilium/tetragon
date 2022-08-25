// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package observer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/tetragon/pkg/api/readyapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/cgroups"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics/ringbufmetrics"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/config"
	"github.com/cilium/tetragon/pkg/sensors/config/confmap"

	"github.com/sirupsen/logrus"
)

const (
	TCP_PROC_STATE_LISTEN = 10

	// Max events to read from each ring in one go. This is used to
	// reduce the likelihood of events being out of order and the
	// limit is required for HTTP/2 parsing to function correctly
	// which relies on frame ordering (it does limited reordering)
	maxEventsPerRing = 4

	perCPUBufferBytes = 65535

	// Use cilium/ebpf to read events from the perf ring. Since we're
	// incrementally rolling this out we're keeping the old code functional
	// in case we need to quickly roll back.
	useCiliumEbpfReader = true
)

var (
	pollTimeout = 5 * time.Second

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

func (k *Observer) receiveEvent(data []byte, cpu int) {
	var op = data[0]

	k.recvCntr++
	r := bytes.NewReader(data)

	// These ops handlers are registered by RegisterEventHandlerAtInit().
	if h, ok := eventHandler[op]; ok {
		if events, err := h(r); err == nil {
			for _, event := range events {
				k.observerListeners(event)
			}
		}
	} else {
		k.log.Infof("unknown op ignored: %v", op)
	}
}

func (k *Observer) __runEvents(stopCtx context.Context) (*bpf.PerCpuEvents, error) {
	e, err := bpf.NewPerCpuEvents(k.perfConfig, k.log)
	if err != nil {
		return nil, fmt.Errorf("failed kprobe events NewPerCpuEvents: %w", err)
	}
	return e, nil
}

func (k *Observer) observerLost(msg *bpf.PerfEventLost, cpu int) {
	k.lostCntr++
}

func (k *Observer) observerError(msg *bpf.PerfEvent) {
	k.errorCntr++
}

func isCtxDone(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

func (k *Observer) __loopEvents(stopCtx context.Context, e *bpf.PerCpuEvents) error {
	receiveEvent := func(msg *bpf.PerfEventSample, cpu int) { k.receiveEvent(msg.DataDirect(), cpu) }
	observerLost := k.observerLost
	observerError := k.observerError
	pollTimeoutMsec := int(pollTimeout / time.Millisecond)

	k.log.Info("Listening for events...")
	k.observerListeners(&readyapi.MsgTetragonReady{})

	for !isCtxDone(stopCtx) {
		_, err := e.Poll(pollTimeoutMsec)
		switch {
		case isCtxDone(stopCtx):
			k.log.Debug("Context cancelled inside __loopEvents")
			return nil

		case errors.Is(err, syscall.EBADF):
			return fmt.Errorf("kprobe events syscall.EBADF: %w", err)

		case err != nil:
			k.log.WithError(err).Debug("kprobe events poll failed")
			continue
		}

		if err := e.ReadAll(maxEventsPerRing, receiveEvent, observerLost, observerError); err != nil {
			k.log.WithError(err).Warn("kprobe events read failed")
		}

		ringbufmetrics.ReceivedSet(float64(k.recvCntr))
		ringbufmetrics.LostSet(float64(k.lostCntr))
		ringbufmetrics.ErrorsSet(float64(k.errorCntr))
	}
	return nil
}

func (k *Observer) runEvents(stopCtx context.Context) error {
	e, err := k.__runEvents(stopCtx)
	if err != nil {
		return err
	}
	defer e.CloseAll()

	err = k.probeTetragonCgroups()
	if err != nil {
		return err
	}

	k.__loopEvents(stopCtx, e)
	return nil
}

func (k *Observer) runEventsNew(stopCtx context.Context, ready func()) error {
	pinOpts := ebpf.LoadPinOptions{}

	perfMap, err := ebpf.LoadPinnedMap(k.perfConfig.MapName, &pinOpts)
	if err != nil {
		return fmt.Errorf("opening pinned map '%s' failed: %w", k.perfConfig.MapName, err)
	}
	defer perfMap.Close()

	perfReader, err := perf.NewReader(perfMap, perCPUBufferBytes)
	if err != nil {
		return fmt.Errorf("creating perf array reader failed: %w", err)
	}

	err = k.probeTetragonCgroups()
	if err != nil {
		return err
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
				// NOTE(JM): Keeping the old behaviour for now and just counting the errors without stopping
				if stopCtx.Err() == nil {
					k.errorCntr++
					ringbufmetrics.ErrorsSet(float64(k.errorCntr))
					k.log.WithError(err).Warn("kprobe events read failed")
				}
			} else {
				if len(record.RawSample) > 0 {
					k.receiveEvent(record.RawSample, record.CPU)
					ringbufmetrics.ReceivedSet(float64(k.recvCntr))
				}

				if record.LostSamples > 0 {
					k.lostCntr += int(record.LostSamples)
					ringbufmetrics.LostSet(float64(k.lostCntr))
				}
			}
		}
		k.log.WithError(stopCtx.Err()).Info("Listening for events completed.")
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
	lostCntr   int
	errorCntr  int
	recvCntr   int
	filterPass int
	filterDrop int
	/* Filters */
	log logrus.FieldLogger

	/* YAML Configuration File */
	configFile string
}

// Update TetragonConf map with environment configuration
func (k *Observer) updateTetragonConf() error {
	pid := os.Getpid()
	err := confmap.UpdateTetragonConfMap(option.Config.MapDir, pid)
	if err != nil {
		// Do not fail
		k.log.WithField("observer", "confmap-update").WithError(err).Warn("Update TetragonConf map failed, advanced Cgroups tracking will be disabled")
		k.log.WithField("observer", "confmap-update").Warn("Continuing without advanced Cgroups tracking. Process association with Pods and Containers might be limited")
	}

	return nil
}

// Migrate Tetragon to its own cgroup to generate a tracepoint
func (k *Observer) probeTetragonCgroups() error {
	err := cgroups.MigrateSelfToSameCgrp()
	if err != nil {
		// Do not fail
		k.log.WithField("observer", "probe-cgroups").WithError(err).Warn("Migrating Tetragon to same Cgroup failed, advanced Cgroups tracking will be disabled")
		k.log.WithField("observer", "probe-cgroups").Warn("Continuing without advanced Cgroups tracking. Process association with Pods and Containers might be limited")
	}

	return nil
}

func (k *Observer) Start(ctx context.Context, sens []*sensors.Sensor) error {
	k.startUpdateMapMetrics()

	if sens != nil {
		if err := config.LoadConfig(ctx, option.Config.BpfDir, option.Config.MapDir, option.Config.CiliumDir, sens); err != nil {
			return err
		}
	}

	if SensorManager == nil {
		if err := k.InitSensorManager(); err != nil {
			return err
		}
	}

	k.perfConfig = bpf.DefaultPerfEventConfig()

	/* Probe runtime configuration */
	err := k.updateTetragonConf()
	if err != nil {
		return err
	}

	if useCiliumEbpfReader {
		err = k.runEventsNew(ctx, func() {})
	} else {
		err = k.runEvents(ctx)
	}
	if err != nil {
		return fmt.Errorf("tetragon, aborting runtime error: %w", err)
	}
	return nil
}

// InitSensorManager starts the sensor controller and stt manager.
func (k *Observer) InitSensorManager() error {
	var err error
	SensorManager, err = sensors.StartSensorManager(option.Config.BpfDir, option.Config.MapDir, option.Config.CiliumDir)
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

func (k *Observer) PrintStats() {
	k.log.Infof("Observer Stats: errors %d lost %d recvd %d filterPass %d filterDrop %d",
		k.errorCntr, k.lostCntr, k.recvCntr, k.filterPass, k.filterDrop)
}

func (k *Observer) RemovePrograms() {
	RemovePrograms(option.Config.BpfDir, option.Config.MapDir)
}
