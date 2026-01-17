// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package slogger

import (
	"context"
	"log/slog"
	"sync"
)

// RecordingHandler is a slog.Handler that records log entries for testing.
// It can filter by level and store messages for later inspection.
// When exactLevel is true, only messages at exactly the specified level are recorded.
// When exactLevel is false, messages at or above the specified level are recorded.
type RecordingHandler struct {
	mu         sync.Mutex
	level      Level
	exactLevel bool
	messages   []string
	records    []slog.Record
	attrs      []slog.Attr
	groups     []string
}

// NewRecordingHandler creates a handler that records messages at exactly the specified level.
// This is useful for testing where you want to capture only messages at a specific level.
func NewRecordingHandler(level Level) *RecordingHandler {
	return &RecordingHandler{
		level:      level,
		exactLevel: true,
		messages:   nil,
		records:    nil,
	}
}

// NewRecordingHandlerAtOrAbove creates a handler that records messages at or above the specified level.
func NewRecordingHandlerAtOrAbove(level Level) *RecordingHandler {
	return &RecordingHandler{
		level:      level,
		exactLevel: false,
		messages:   nil,
		records:    nil,
	}
}

// Enabled reports whether the handler handles records at the given level.
func (h *RecordingHandler) Enabled(_ context.Context, level slog.Level) bool {
	if h.exactLevel {
		return level == h.level
	}
	return level >= h.level
}

// Handle records the log message.
func (h *RecordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	shouldRecord := false
	if h.exactLevel {
		shouldRecord = r.Level == h.level
	} else {
		shouldRecord = r.Level >= h.level
	}
	if shouldRecord {
		h.messages = append(h.messages, r.Message)
		h.records = append(h.records, r)
	}
	return nil
}

// WithAttrs returns a new handler with the given attributes added.
func (h *RecordingHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	h.mu.Lock()
	defer h.mu.Unlock()
	newAttrs := make([]slog.Attr, len(h.attrs), len(h.attrs)+len(attrs))
	copy(newAttrs, h.attrs)
	newAttrs = append(newAttrs, attrs...)
	return &RecordingHandler{
		level:      h.level,
		exactLevel: h.exactLevel,
		messages:   h.messages, // share the slice for recording
		records:    h.records,
		attrs:      newAttrs,
		groups:     h.groups,
	}
}

// WithGroup returns a new handler with the given group name.
func (h *RecordingHandler) WithGroup(name string) slog.Handler {
	h.mu.Lock()
	defer h.mu.Unlock()
	newGroups := make([]string, len(h.groups), len(h.groups)+1)
	copy(newGroups, h.groups)
	newGroups = append(newGroups, name)
	return &RecordingHandler{
		level:      h.level,
		exactLevel: h.exactLevel,
		messages:   h.messages,
		records:    h.records,
		attrs:      h.attrs,
		groups:     newGroups,
	}
}

// Messages returns all recorded messages.
func (h *RecordingHandler) Messages() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	result := make([]string, len(h.messages))
	copy(result, h.messages)
	return result
}

// Records returns all recorded log records.
func (h *RecordingHandler) Records() []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	result := make([]slog.Record, len(h.records))
	copy(result, h.records)
	return result
}

// Clear removes all recorded messages and records.
func (h *RecordingHandler) Clear() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.messages = h.messages[:0]
	h.records = h.records[:0]
}

// MultiHandler combines multiple handlers, routing logs to all of them.
// This is useful for testing where you want to capture logs at different levels.
type MultiHandler struct {
	handlers []slog.Handler
}

// NewMultiHandler creates a handler that routes to multiple handlers.
func NewMultiHandler(handlers ...slog.Handler) *MultiHandler {
	return &MultiHandler{handlers: handlers}
}

// Enabled reports whether any handler handles records at the given level.
func (h *MultiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, handler := range h.handlers {
		if handler.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

// Handle sends the record to all handlers.
func (h *MultiHandler) Handle(ctx context.Context, r slog.Record) error {
	for _, handler := range h.handlers {
		if handler.Enabled(ctx, r.Level) {
			if err := handler.Handle(ctx, r); err != nil {
				return err
			}
		}
	}
	return nil
}

// WithAttrs returns a new MultiHandler with the given attributes added to all handlers.
func (h *MultiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newHandlers := make([]slog.Handler, len(h.handlers))
	for i, handler := range h.handlers {
		newHandlers[i] = handler.WithAttrs(attrs)
	}
	return &MultiHandler{handlers: newHandlers}
}

// WithGroup returns a new MultiHandler with the given group name added to all handlers.
func (h *MultiHandler) WithGroup(name string) slog.Handler {
	newHandlers := make([]slog.Handler, len(h.handlers))
	for i, handler := range h.handlers {
		newHandlers[i] = handler.WithGroup(name)
	}
	return &MultiHandler{handlers: newHandlers}
}

// DiscardHandler is a handler that discards all logs.
type DiscardHandler struct{}

// Enabled always returns true (all levels accepted).
func (h *DiscardHandler) Enabled(_ context.Context, _ slog.Level) bool {
	return true
}

// Handle discards the record.
func (h *DiscardHandler) Handle(_ context.Context, _ slog.Record) error {
	return nil
}

// WithAttrs returns the same handler (no-op).
func (h *DiscardHandler) WithAttrs(_ []slog.Attr) slog.Handler {
	return h
}

// WithGroup returns the same handler (no-op).
func (h *DiscardHandler) WithGroup(_ string) slog.Handler {
	return h
}

// NewDiscard creates a Logger that discards all output.
func NewDiscard() Logger {
	return NewWithHandler(&DiscardHandler{})
}
