// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package logger

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"

	"github.com/cilium/tetragon/pkg/logger/logfields"
)

// logrErrorKey is the key used by the logr library for the error parameter.
const logrErrorKey = "err"

// SlogNopHandler discards all logs.
var SlogNopHandler slog.Handler = nopHandler{}

type nopHandler struct{}

func (nopHandler) Enabled(context.Context, slog.Level) bool  { return false }
func (nopHandler) Handle(context.Context, slog.Record) error { return nil }
func (n nopHandler) WithAttrs([]slog.Attr) slog.Handler      { return n }
func (n nopHandler) WithGroup(string) slog.Handler           { return n }

var slogHandlerOpts = &slog.HandlerOptions{
	AddSource:   false,
	Level:       slogLeveler,
	ReplaceAttr: replaceAttrFnWithoutTimestamp,
}

// DefaultSlogLogger is for convenient usage. Will be overwritten once initializeSlog is called.
var DefaultSlogLogger = slog.New(slog.NewTextHandler(
	os.Stderr,
	slogHandlerOpts,
))

var slogLeveler = func() *slog.LevelVar {
	var levelVar slog.LevelVar
	levelVar.Set(slog.LevelInfo)
	return &levelVar
}()

// initializeSlog approximates the logrus output via slog for job groups during the transition
// phase.
func initializeSlog(logOpts LogOptions, useStdout bool) {
	opts := *slogHandlerOpts
	lv := logOpts.GetLogLevel()
	SetLogLevel(lv)

	if lv == slog.LevelDebug {
		opts.AddSource = true
	}

	logFormat := logOpts.GetLogFormat()
	switch logFormat {
	case logFormatJSON, logFormatText:
		opts.ReplaceAttr = replaceAttrFnWithoutTimestamp
	case logFormatJSONTimestamp, logFormatTextTimestamp:
		opts.ReplaceAttr = replaceAttrFn
	}

	writer := os.Stderr
	if useStdout {
		writer = os.Stdout
	}

	switch logFormat {
	case logFormatJSON, logFormatJSONTimestamp:
		DefaultSlogLogger = slog.New(slog.NewJSONHandler(
			writer,
			&opts,
		))
	case logFormatText, logFormatTextTimestamp:
		DefaultSlogLogger = slog.New(slog.NewTextHandler(
			writer,
			&opts,
		))
	}
}

func replaceAttrFn(_ []string, a slog.Attr) slog.Attr {
	switch a.Key {
	case slog.TimeKey:
		// Adjust to timestamp format that logrus uses; except that we can't
		// force slog to quote the value like logrus does...
		return slog.String(slog.TimeKey, a.Value.Time().Format(time.RFC3339))
	case slog.LevelKey:
		// Lower-case the log level
		return slog.Attr{
			Key:   a.Key,
			Value: slog.StringValue(strings.ToLower(a.Value.String())),
		}
	case logrErrorKey:
		// Uniform the attribute identifying the error
		return slog.Attr{
			Key:   logfields.Error,
			Value: a.Value,
		}
	}
	return a
}

func replaceAttrFnWithoutTimestamp(groups []string, a slog.Attr) slog.Attr {
	switch a.Key {
	case slog.TimeKey:
		// Drop timestamps
		return slog.Attr{}
	default:
		return replaceAttrFn(groups, a)
	}
}

func NewLogrFromSlog(logger *slog.Logger) logr.Logger {
	return logr.New(logSink{logr.FromSlogHandler(logger.Handler()).GetSink()})
}

type logSink struct{ logr.LogSink }

func (w logSink) Error(err error, msg string, keysAndValues ...any) {
	w.LogSink.Error(err, msg, keysAndValues...)
}

func (w logSink) WithValues(keysAndValues ...any) logr.LogSink {
	return logSink{w.LogSink.WithValues(keysAndValues...)}
}

func (w logSink) WithName(name string) logr.LogSink {
	return logSink{w.LogSink.WithName(name)}
}

type FieldLogger interface {
	Handler() slog.Handler
	With(args ...any) *slog.Logger
	WithGroup(name string) *slog.Logger
	Enabled(ctx context.Context, level slog.Level) bool
	Log(ctx context.Context, level slog.Level, msg string, args ...any)
	LogAttrs(ctx context.Context, level slog.Level, msg string, attrs ...slog.Attr)
	Debug(msg string, args ...any)
	DebugContext(ctx context.Context, msg string, args ...any)
	Info(msg string, args ...any)
	InfoContext(ctx context.Context, msg string, args ...any)
	Warn(msg string, args ...any)
	WarnContext(ctx context.Context, msg string, args ...any)
	Error(msg string, args ...any)
	ErrorContext(ctx context.Context, msg string, args ...any)
}

func init() {
	// Set a no-op exit handler to avoid nil dereference
	a := func() {}
	exitHandler.Store(&a)
}

var (
	exitHandler atomic.Pointer[func()]
)

func Trace(logger FieldLogger, msg string, args ...any) {
	logger.Log(context.Background(), LevelTrace, msg, args...)
}

func Fatal(logger FieldLogger, msg string, args ...any) {
	logger.Error(msg, args...)
	(*exitHandler.Load())()
	os.Exit(-1)
}

func Panic(logger FieldLogger, msg string, args ...any) {
	logger.Error(msg, args...)
	(*exitHandler.Load())()
	panic(msg)
}

func RegisterExitHandler(handler func()) {
	exitHandler.Store(&handler)
}
