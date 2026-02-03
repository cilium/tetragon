// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// reading_observer.go implements ReadingObserver that reads and replays Tetragon events
// from a reader. It implements the observer.EventObserver interface.

package synthetic

import (
	"bufio"
	"context"
	"io"
	"sync/atomic"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/reader/notify"
)

// ReadingObserver reads and replays synthetic events from a reader.
// It implements observer.EventObserver interface.
type ReadingObserver struct {
	*observer.Observer
	reader    io.Reader
	codec     Codec
	log       logger.FieldLogger
	listeners map[observer.Listener]struct{}
	events    uint64
	errors    uint64
}

// NewReadingObserver creates a new ReadingObserver with the given reader, codec and logger.
func NewReadingObserver(reader io.Reader, codec Codec, log logger.FieldLogger) *ReadingObserver {
	return &ReadingObserver{
		reader:    reader,
		codec:     codec,
		log:       log,
		listeners: make(map[observer.Listener]struct{}),
	}
}

// StartReady implements observer.EventObserver.StartReady.
func (r *ReadingObserver) StartReady(ctx context.Context, ready func()) error {
	ready()

	r.log.Info("Starting synthetic event replay")

	scanner := bufio.NewScanner(r.reader)
	for scanner.Scan() {
		if ctx.Err() != nil {
			break
		}

		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		// Unmarshal the event using codec
		event, err := r.codec.Unmarshal(line)
		if err != nil {
			r.log.Warn("Failed to unmarshal event", "error", err)
			atomic.AddUint64(&r.errors, 1)
			continue
		}

		msg, ok := event.(notify.Message)
		if !ok {
			r.log.Warn("Event does not implement notify.Message")
			atomic.AddUint64(&r.errors, 1)
			continue
		}

		atomic.AddUint64(&r.events, 1)
		r.observerListeners(msg)
	}

	r.log.Info("Finished synthetic event replay", "events", atomic.LoadUint64(&r.events))

	// Keep running until context is cancelled
	<-ctx.Done()
	return nil
}

// observerListeners sends a message to all registered listeners.
func (r *ReadingObserver) observerListeners(msg notify.Message) {
	for listener := range r.listeners {
		if err := listener.Notify(msg); err != nil {
			r.log.Debug("Write failure removing Listener")
			r.RemoveListener(listener)
		}
	}
}

// AddListener implements observer.EventObserver.AddListener.
func (r *ReadingObserver) AddListener(listener observer.Listener) {
	r.log.Debug("Add listener", "listener", listener)
	r.listeners[listener] = struct{}{}
}

// RemoveListener implements observer.EventObserver.RemoveListener.
func (r *ReadingObserver) RemoveListener(listener observer.Listener) {
	r.log.Debug("Delete listener", "listener", listener)
	delete(r.listeners, listener)
	if err := listener.Close(); err != nil {
		r.log.Warn("failed to close listener", logfields.Error, err)
	}
}
