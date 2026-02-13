// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"context"
	"log/slog"
)

type eventCheckerLogger struct {
	handler slog.Handler
}

func (h *eventCheckerLogger) Enabled(ctx context.Context, level slog.Level) bool {
	// for info level, check if the log handler has debug enabled
	if level == slog.LevelInfo {
		return h.handler.Enabled(ctx, slog.LevelDebug)
	}
	return h.handler.Enabled(ctx, level)
}

func (h *eventCheckerLogger) Handle(ctx context.Context, record slog.Record) error {
	return h.handler.Handle(ctx, record)
}

func (h *eventCheckerLogger) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &eventCheckerLogger{handler: h.handler.WithAttrs(attrs)}
}

func (h *eventCheckerLogger) WithGroup(name string) slog.Handler {
	return &eventCheckerLogger{handler: h.handler.WithGroup(name)}
}
