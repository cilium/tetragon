// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package logger

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/go-logr/logr"
	"github.com/sirupsen/logrus"
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
	Level:       slog.LevelInfo,
	ReplaceAttr: replaceAttrFnWithoutTimestamp,
}

// DefaultSlogLogger is for convenient usage. Will be overwritten once initializeSlog is called.
var DefaultSlogLogger = slog.New(slog.NewTextHandler(
	os.Stderr,
	slogHandlerOpts,
))

func slogLevel(l logrus.Level) slog.Level {
	switch l {
	case logrus.DebugLevel, logrus.TraceLevel:
		return slog.LevelDebug
	case logrus.InfoLevel:
		return slog.LevelInfo
	case logrus.WarnLevel:
		return slog.LevelWarn
	case logrus.ErrorLevel, logrus.PanicLevel, logrus.FatalLevel:
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// InitializeSlog approximates the logrus output via slog for job groups during the transition
// phase.
func InitializeSlog(logOpts LogOptions, useStdout bool) {
	opts := *slogHandlerOpts
	opts.Level = slogLevel(logOpts.getLogLevel())

	logFormat := logOpts.getLogFormat()
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
