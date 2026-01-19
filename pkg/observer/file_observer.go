// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package observer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"sync"
	"sync/atomic"

	"github.com/cilium/tetragon/pkg/api/readyapi"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/cilium/tetragon/pkg/sensors"
)

type FileObserver struct {
	listeners map[Listener]struct{}
	mu        sync.RWMutex
	log       logger.FieldLogger
	events    uint64
	errors    uint64
}

// SyntheticEvent represents a logged event with base64-encoded raw binary data
type SyntheticEvent struct {
	Data string `json:"data"` // base64-encoded raw binary event data
}

func NewFileObserver() *FileObserver {
	return &FileObserver{
		listeners: make(map[Listener]struct{}),
		log:       logger.GetLogger(),
		events:    0,
		errors:    0,
	}
}

func (k *FileObserver) Start(ctx context.Context) error {
	return k.StartReady(ctx, func() {})
}

func (k *FileObserver) StartReady(ctx context.Context, ready func()) error {
	// Notify ready
	k.observerListeners(&readyapi.MsgTetragonReady{})
	ready()

	k.log.Info("Starting synthetic event injection", "source", option.Config.SyntheticEventsSource)

	f, err := os.Open(option.Config.SyntheticEventsSource)
	if err != nil {
		return err
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	for {
		if ctx.Err() != nil {
			break
		}

		var synev SyntheticEvent
		if err := dec.Decode(&synev); err != nil {
			if err == io.EOF {
				break
			}
			k.log.Warn("Failed to decode JSON event", "error", err)
			atomic.AddUint64(&k.errors, 1)
			continue
		}

		// Decode base64 to get raw binary event data
		data, err := base64.StdEncoding.DecodeString(synev.Data)
		if err != nil {
			k.log.Warn("Failed to decode base64 data", "error", err)
			atomic.AddUint64(&k.errors, 1)
			continue
		}

		// Use HandlePerfData to parse binary data into events (same as real observer)
		_, events, perr := HandlePerfData(data)
		if perr != nil {
			k.log.Warn("Failed to handle perf data", "error", perr)
			atomic.AddUint64(&k.errors, 1)
			continue
		}

		for _, msg := range events {
			if msg != nil {
				atomic.AddUint64(&k.events, 1)
				k.observerListeners(msg)
			}
		}
	}

	k.log.Info("Finished synthetic event injection", "events", atomic.LoadUint64(&k.events))

	// Keep running until context is cancelled
	<-ctx.Done()
	return nil
}

func (k *FileObserver) observerListeners(msg notify.Message) {
	k.mu.RLock()
	listeners := make([]Listener, 0, len(k.listeners))
	for listener := range k.listeners {
		listeners = append(listeners, listener)
	}
	k.mu.RUnlock()

	for _, listener := range listeners {
		if err := listener.Notify(msg); err != nil {
			k.log.Debug("Write failure removing Listener")
			k.RemoveListener(listener)
		}
	}
}

func (k *FileObserver) InitSensorManager() error {
	mgr, err := sensors.StartSensorManager(option.Config.BpfDir)
	if err != nil {
		return err
	}
	return SetSensorManager(mgr)
}

func (k *FileObserver) UpdateRuntimeConf(bpfDir string) error {
	return nil
}

func (k *FileObserver) AddListener(listener Listener) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.log.Debug("Add listener", "listener", listener)
	k.listeners[listener] = struct{}{}
}

func (k *FileObserver) RemoveListener(listener Listener) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.log.Debug("Delete listener", "listener", listener)
	delete(k.listeners, listener)
	if err := listener.Close(); err != nil {
		k.log.Warn("failed to close listener", logfields.Error, err)
	}
}

func (k *FileObserver) PrintStats() {
	k.log.Info("FileObserver stats",
		"events", atomic.LoadUint64(&k.events),
		"errors", atomic.LoadUint64(&k.errors),
	)
}

func (k *FileObserver) LogPinnedBpf(observerDir string) {
	// No-op
}

func (k *FileObserver) ReadLostEvents() uint64 {
	return 0
}

func (k *FileObserver) ReadErrorEvents() uint64 {
	return atomic.LoadUint64(&k.errors)
}
