// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Package observer defines interfaces for the observer subsystem.
package observer

import (
	"context"
	"io"

	"github.com/cilium/tetragon/pkg/reader/notify"
)

// Listener defines the interface to receive events from Observer. Listeners
// will merge and complete out-of-order events before they're passed to
// human-readable sinks such as the printer or GRPC encoder.
type Listener interface {
	// Notify gets called for each events from ObserverKprobe.
	Notify(msg notify.Message) error

	// Close the listener.
	io.Closer
}

// EventObserver defines the interface for event observation and processing.
type EventObserver interface {
	Start(ctx context.Context) error
	StartReady(ctx context.Context, ready func()) error
	InitSensorManager() error
	UpdateRuntimeConf(bpfDir string) error
	AddListener(listener Listener)
	RemoveListener(listener Listener)
	PrintStats()
	LogPinnedBpf(observerDir string)
	ReadLostEvents() uint64
	ReadErrorEvents() uint64
}
