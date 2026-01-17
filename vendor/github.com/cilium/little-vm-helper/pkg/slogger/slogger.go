// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package slogger provides a structured logging abstraction using Go's log/slog.
// It provides an interface Logger that mirrors common logging patterns and
// supports structured logging with fields.
package slogger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
)

// Level represents log severity levels
type Level = slog.Level

// Log levels matching slog's levels
const (
	LevelDebug = slog.LevelDebug
	LevelInfo  = slog.LevelInfo
	LevelWarn  = slog.LevelWarn
	LevelError = slog.LevelError
)

// Logger is the interface for structured logging operations.
// It provides methods for logging at different levels with optional structured fields.
type Logger interface {
	// WithField returns a new Logger with the given field added
	WithField(key string, value any) Logger
	// WithFields returns a new Logger with the given fields added
	WithFields(fields map[string]any) Logger
	// WithError returns a new Logger with an error field added
	WithError(err error) Logger

	// Log methods
	Debug(msg string)
	Debugf(format string, args ...any)
	Info(msg string)
	Infof(format string, args ...any)
	Warn(msg string)
	Warnf(format string, args ...any)
	Error(msg string)
	Errorf(format string, args ...any)
	Fatal(v any)
	Fatalf(format string, args ...any)
	Panic(v any)
	Panicf(format string, args ...any)

	// Handler returns the underlying slog.Handler for advanced use cases
	Handler() slog.Handler
	// SetOutput changes the output destination (for testing)
	SetOutput(w io.Writer)
}

// logger is the default implementation of Logger using slog
type logger struct {
	slog   *slog.Logger
	attrs  []slog.Attr
	output io.Writer
	level  *slog.LevelVar
}

// New creates a new Logger with default settings (text handler, stdout)
func New() Logger {
	level := &slog.LevelVar{}
	level.Set(LevelInfo)
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	})
	return &logger{
		slog:   slog.New(handler),
		attrs:  nil,
		output: os.Stderr,
		level:  level,
	}
}

// NewWithHandler creates a new Logger with a custom handler
func NewWithHandler(handler slog.Handler) Logger {
	return &logger{
		slog:  slog.New(handler),
		attrs: nil,
	}
}

// NewWithLevel creates a new Logger with a specified log level
func NewWithLevel(level Level) Logger {
	levelVar := &slog.LevelVar{}
	levelVar.Set(level)
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: levelVar,
	})
	return &logger{
		slog:   slog.New(handler),
		attrs:  nil,
		output: os.Stderr,
		level:  levelVar,
	}
}

func (l *logger) WithField(key string, value any) Logger {
	newAttrs := make([]slog.Attr, len(l.attrs), len(l.attrs)+1)
	copy(newAttrs, l.attrs)
	newAttrs = append(newAttrs, slog.Any(key, value))
	return &logger{
		slog:   l.slog,
		attrs:  newAttrs,
		output: l.output,
		level:  l.level,
	}
}

func (l *logger) WithFields(fields map[string]any) Logger {
	newAttrs := make([]slog.Attr, len(l.attrs), len(l.attrs)+len(fields))
	copy(newAttrs, l.attrs)
	for k, v := range fields {
		newAttrs = append(newAttrs, slog.Any(k, v))
	}
	return &logger{
		slog:   l.slog,
		attrs:  newAttrs,
		output: l.output,
		level:  l.level,
	}
}

func (l *logger) WithError(err error) Logger {
	return l.WithField("error", err)
}

func (l *logger) log(level Level, msg string) {
	if l.slog.Enabled(context.Background(), level) {
		args := make([]any, 0, len(l.attrs)*2)
		for _, attr := range l.attrs {
			args = append(args, attr.Key, attr.Value.Any())
		}
		l.slog.Log(context.Background(), level, msg, args...)
	}
}

func (l *logger) logf(level Level, format string, fmtArgs ...any) {
	if l.slog.Enabled(context.Background(), level) {
		msg := formatMessage(format, fmtArgs...)
		args := make([]any, 0, len(l.attrs)*2)
		for _, attr := range l.attrs {
			args = append(args, attr.Key, attr.Value.Any())
		}
		l.slog.Log(context.Background(), level, msg, args...)
	}
}

func (l *logger) Debug(msg string) {
	l.log(LevelDebug, msg)
}

func (l *logger) Debugf(format string, args ...any) {
	l.logf(LevelDebug, format, args...)
}

func (l *logger) Info(msg string) {
	l.log(LevelInfo, msg)
}

func (l *logger) Infof(format string, args ...any) {
	l.logf(LevelInfo, format, args...)
}

func (l *logger) Warn(msg string) {
	l.log(LevelWarn, msg)
}

func (l *logger) Warnf(format string, args ...any) {
	l.logf(LevelWarn, format, args...)
}

func (l *logger) Error(msg string) {
	l.log(LevelError, msg)
}

func (l *logger) Errorf(format string, args ...any) {
	l.logf(LevelError, format, args...)
}

func (l *logger) Fatal(v any) {
	msg := fmt.Sprint(v)
	l.log(LevelError, msg)
	os.Exit(1)
}

func (l *logger) Fatalf(format string, args ...any) {
	l.logf(LevelError, format, args...)
	os.Exit(1)
}

func (l *logger) Panic(v any) {
	msg := fmt.Sprint(v)
	l.log(LevelError, msg)
	panic(msg)
}

func (l *logger) Panicf(format string, args ...any) {
	msg := formatMessage(format, args...)
	l.log(LevelError, msg)
	panic(msg)
}

func (l *logger) Handler() slog.Handler {
	return l.slog.Handler()
}

func (l *logger) SetOutput(w io.Writer) {
	l.output = w
	var handler slog.Handler
	if l.level != nil {
		handler = slog.NewTextHandler(w, &slog.HandlerOptions{
			Level: l.level,
		})
	} else {
		handler = slog.NewTextHandler(w, nil)
	}
	l.slog = slog.New(handler)
}

// formatMessage formats a message with arguments, similar to fmt.Sprintf
func formatMessage(format string, args ...any) string {
	if len(args) == 0 {
		return format
	}
	return fmt.Sprintf(format, args...)
}
