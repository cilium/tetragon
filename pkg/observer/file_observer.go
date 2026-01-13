// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package observer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/tetragon/pkg/api/readyapi"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/cilium/tetragon/pkg/sensors"
)

type SyntheticEvent struct {
	Type  string          `json:"type"`
	Ktime uint64          `json:"ktime"`
	Event json.RawMessage `json:"event"`
}

type SyntheticUnmarshaler func(json.RawMessage) (notify.Message, error)

var (
	syntheticUnmarshalers = make(map[string]SyntheticUnmarshaler)
)

func RegisterSyntheticUnmarshaler(eventType string, u SyntheticUnmarshaler) {
	syntheticUnmarshalers[eventType] = u
}

type FileObserver struct {
	listeners map[Listener]struct{}
	mu        sync.RWMutex
	log       logger.FieldLogger
	events    uint64
	errors    uint64
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
	k.NotifyListeners(&readyapi.MsgTetragonReady{})
	ready()

	k.log.Info("Starting synthetic event injection", "source", option.Config.SyntheticEventsSource)

	f, err := os.Open(option.Config.SyntheticEventsSource)
	if err != nil {
		return err
	}
	defer f.Close()

	dec := json.NewDecoder(f)

	// Check if it's an array start
	t, err := dec.Token()
	if err != nil {
		return err
	}
	if delim, ok := t.(json.Delim); !ok || delim != '[' {
		return fmt.Errorf("expected JSON array start")
	}

	var firstKtime uint64
	var startTime time.Time

	for dec.More() {
		if ctx.Err() != nil {
			break
		}

		var wrapper SyntheticEvent
		if err := dec.Decode(&wrapper); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		unmarshaler, ok := syntheticUnmarshalers[wrapper.Type]
		if !ok {
			logger.GetLogger().Warn("Unknown synthetic event type", "type", wrapper.Type)
			atomic.AddUint64(&k.errors, 1)
			continue
		}

		msg, err := unmarshaler(wrapper.Event)
		if err != nil {
			k.log.Warn("Failed to unmarshal event", "type", wrapper.Type, "error", err)
			atomic.AddUint64(&k.errors, 1)
			continue
		}

		if msg != nil {
			ktime := wrapper.Ktime
			if ktime != 0 {
				if firstKtime == 0 {
					firstKtime = ktime
					startTime = time.Now()
				} else {
					// Calculate how much time should have passed since the first event
					targetDuration := time.Duration(ktime - firstKtime)
					// Calculate how much time has actually passed
					elapsed := time.Since(startTime)
					// Sleep the difference if we are ahead of schedule
					if targetDuration > elapsed {
						select {
						case <-time.After(targetDuration - elapsed):
						case <-ctx.Done():
							return nil
						}
					}
				}
			}
			atomic.AddUint64(&k.events, 1)
			k.NotifyListeners(msg)
		}
	}

	// Token closing array
	_, _ = dec.Token()

	k.log.Info("Finished synthetic event injection", "events", atomic.LoadUint64(&k.events))

	// Keep running until context is cancelled
	<-ctx.Done()
	return nil
}

func (k *FileObserver) NotifyListeners(msg notify.Message) {
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
