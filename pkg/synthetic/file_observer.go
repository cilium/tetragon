// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package synthetic

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"sync"
	"sync/atomic"

	"github.com/cilium/tetragon/pkg/api/readyapi"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/observertypes"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/cilium/tetragon/pkg/sensors"
)

// FileObserver reads and replays synthetic events from a file.
// It implements observer.EventObserver interface.
type FileObserver struct {
	listeners map[observertypes.Listener]struct{}
	mu        sync.RWMutex
	log       logger.FieldLogger
	events    uint64
	errors    uint64

	sensorManager *sensors.Manager
}

// NewFileObserver creates a new synthetic event FileObserver.
func NewFileObserver() *FileObserver {
	return &FileObserver{
		listeners: make(map[observertypes.Listener]struct{}),
		log:       logger.GetLogger(),
		events:    0,
		errors:    0,
	}
}

// Start implements observer.EventObserver.Start.
func (r *FileObserver) Start(ctx context.Context) error {
	return r.StartReady(ctx, func() {})
}

// StartReady implements observer.EventObserver.StartReady.
func (r *FileObserver) StartReady(ctx context.Context, ready func()) error {
	// Notify ready
	r.observerListeners(&readyapi.MsgTetragonReady{})
	ready()

	r.log.Info("Starting synthetic event replay", "source", option.Config.SyntheticEventsSource)

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

		var synev Event
		if err := dec.Decode(&synev); err != nil {
			if err == io.EOF {
				break
			}
			r.log.Warn("Failed to decode JSON event", "error", err)
			atomic.AddUint64(&r.errors, 1)
			continue
		}

		// Get factory for this event type
		factory, ok := TypeRegistry[synev.Type]
		if !ok {
			r.log.Warn("Unknown synthetic event type", "type", synev.Type)
			atomic.AddUint64(&r.errors, 1)
			continue
		}

		// Create new event instance and unmarshal JSON into it
		event := factory()
		if err := json.Unmarshal(synev.Event, event); err != nil {
			r.log.Warn("Failed to unmarshal event", "type", synev.Type, "error", err)
			atomic.AddUint64(&r.errors, 1)
			continue
		}

		atomic.AddUint64(&r.events, 1)
		r.observerListeners(event)
	}

	r.log.Info("Finished synthetic event replay", "events", atomic.LoadUint64(&r.events))

	// Keep running until context is cancelled
	<-ctx.Done()
	return nil
}

// observerListeners sends a message to all registered listeners.
func (r *FileObserver) observerListeners(msg notify.Message) {
	r.mu.RLock()
	listeners := make([]observertypes.Listener, 0, len(r.listeners))
	for listener := range r.listeners {
		listeners = append(listeners, listener)
	}
	r.mu.RUnlock()

	for _, listener := range listeners {
		if err := listener.Notify(msg); err != nil {
			r.log.Debug("Write failure removing Listener")
			r.RemoveListener(listener)
		}
	}
}

// InitSensorManager implements observer.EventObserver.InitSensorManager.
func (r *FileObserver) InitSensorManager() error {
	mgr, err := sensors.StartSensorManager(option.Config.BpfDir)
	if err != nil {
		return err
	}
	r.sensorManager = mgr
	return observer.SetSensorManager(mgr)
}

// GetSensorManager returns the sensor manager.
func (r *FileObserver) GetSensorManager() *sensors.Manager {
	return r.sensorManager
}

// UpdateRuntimeConf implements observer.EventObserver.UpdateRuntimeConf.
func (r *FileObserver) UpdateRuntimeConf(bpfDir string) error {
	return nil
}

// AddListener implements observer.EventObserver.AddListener.
func (r *FileObserver) AddListener(listener observertypes.Listener) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.log.Debug("Add listener", "listener", listener)
	r.listeners[listener] = struct{}{}
}

// RemoveListener implements observer.EventObserver.RemoveListener.
func (r *FileObserver) RemoveListener(listener observertypes.Listener) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.log.Debug("Delete listener", "listener", listener)
	delete(r.listeners, listener)
	if err := listener.Close(); err != nil {
		r.log.Warn("failed to close listener", logfields.Error, err)
	}
}

// PrintStats implements observer.EventObserver.PrintStats.
func (r *FileObserver) PrintStats() {
	r.log.Info("Synthetic FileObserver stats",
		"events", atomic.LoadUint64(&r.events),
		"errors", atomic.LoadUint64(&r.errors),
	)
}

// LogPinnedBpf implements observer.EventObserver.LogPinnedBpf.
func (r *FileObserver) LogPinnedBpf(observerDir string) {
	// No-op for synthetic file observer
}

// ReadLostEvents implements observer.EventObserver.ReadLostEvents.
func (r *FileObserver) ReadLostEvents() uint64 {
	return 0
}

// ReadErrorEvents implements observer.EventObserver.ReadErrorEvents.
func (r *FileObserver) ReadErrorEvents() uint64 {
	return atomic.LoadUint64(&r.errors)
}
