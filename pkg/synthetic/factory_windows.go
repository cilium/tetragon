// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package synthetic

import (
	"context"
	"errors"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/reader/notify"
)

var errNotSupported = errors.New("synthetic events are only supported on Linux")

// NewReadingObserverFromFile is not supported on non-Linux platforms.
func NewReadingObserverFromFile(_ context.Context, _ string, _ logger.FieldLogger) (*ReadingObserver, error) {
	return nil, errNotSupported
}

// NewWritingListenerToFile is not supported on non-Linux platforms.
func NewWritingListenerToFile(_ context.Context, _ string, _ logger.FieldLogger, _ ...Option) (*WritingListener, error) {
	return nil, errNotSupported
}

// ReadingObserver stub for non-Linux platforms.
type ReadingObserver struct {
	*observer.Observer
}

// Start stub for non-Linux platforms.
func (r *ReadingObserver) Start(_ context.Context) error { return errNotSupported }

// StartReady stub for non-Linux platforms.
func (r *ReadingObserver) StartReady(_ context.Context, _ func()) error { return errNotSupported }

// InitSensorManager stub for non-Linux platforms.
func (r *ReadingObserver) InitSensorManager() error { return errNotSupported }

// UpdateRuntimeConf stub for non-Linux platforms.
func (r *ReadingObserver) UpdateRuntimeConf(_ string) error { return errNotSupported }

// AddListener stub for non-Linux platforms.
func (r *ReadingObserver) AddListener(_ observer.Listener) {}

// RemoveListener stub for non-Linux platforms.
func (r *ReadingObserver) RemoveListener(_ observer.Listener) {}

// PrintStats stub for non-Linux platforms.
func (r *ReadingObserver) PrintStats() {}

// LogPinnedBpf stub for non-Linux platforms.
func (r *ReadingObserver) LogPinnedBpf(_ string) {}

// ReadLostEvents stub for non-Linux platforms.
func (r *ReadingObserver) ReadLostEvents() uint64 { return 0 }

// ReadErrorEvents stub for non-Linux platforms.
func (r *ReadingObserver) ReadErrorEvents() uint64 { return 0 }

// WritingListener stub for non-Linux platforms.
type WritingListener struct{}

// Notify stub for non-Linux platforms.
func (l *WritingListener) Notify(_ notify.Message) error { return nil }

// Close stub for non-Linux platforms.
func (l *WritingListener) Close() error { return nil }

// Option configures WritingListener.
type Option func(*WritingListener)

// WithVerifyRoundtrip is a no-op on non-Linux platforms.
func WithVerifyRoundtrip(_ bool) Option {
	return func(_ *WritingListener) {}
}

// WithDelegate is a no-op on non-Linux platforms.
func WithDelegate(_ observer.Listener) Option {
	return func(_ *WritingListener) {}
}
