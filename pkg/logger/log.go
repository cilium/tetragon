// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package logger

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/cilium/tetragon/pkg/logger/logfields"
)

type LogFormat string

const (
	LevelOpt  = "level"
	FormatOpt = "format"

	logFormatText          LogFormat = "text"
	logFormatTextTimestamp LogFormat = "text-ts"
	logFormatJSON          LogFormat = "json"
	logFormatJSONTimestamp LogFormat = "json-ts"

	defaultLogFormat LogFormat  = logFormatText
	defaultLogLevel  slog.Level = slog.LevelInfo
)

var (
	LevelTrace = slog.LevelDebug - 4
	LevelPanic = slog.LevelError + 8
	LevelFatal = LevelPanic + 2
)

// LogOptions maps configuration key-value pairs related to logging.
type LogOptions map[string]string

// GetLogLevel returns the log level specified in the provided LogOptions. If
// it is not set in the options, it will return the default level.
func (o LogOptions) GetLogLevel() (level slog.Level) {
	levelOpt, ok := o[LevelOpt]
	if !ok {
		return defaultLogLevel
	}

	var err error
	if level, err = ParseLevel(levelOpt); err != nil {
		DefaultSlogLogger.Warn("Ignoring user-configured log level", logfields.Error, err)
		return defaultLogLevel
	}

	return
}

// GetLogFormat returns the log format specified in the provided LogOptions. If
// it is not set in the options or is invalid, it will return the default format.
func (o LogOptions) GetLogFormat() LogFormat {
	formatOpt, ok := o[FormatOpt]
	if !ok {
		return defaultLogFormat
	}

	formatOpt = strings.ToLower(formatOpt)
	re := regexp.MustCompile(`^(text|text-ts|json|json-ts)$`)
	if !re.MatchString(formatOpt) {
		DefaultSlogLogger.Warn(
			"Ignoring user-configured log format",
			logfields.Error, fmt.Errorf("incorrect log format configured '%s', expected 'text', 'text-ts', 'json' or 'json-ts'", formatOpt),
		)
		return defaultLogFormat
	}

	return LogFormat(formatOpt)
}

// SetLogLevel updates the DefaultLogger with a new slog.Level
func SetLogLevel(logLevel slog.Level) {
	slogLeveler.Set(logLevel)
}

// SetDefaultLogLevel updates the DefaultLogger with the DefaultLogLevel
func SetDefaultLogLevel() {
	SetLogLevel(defaultLogLevel)
}

// SetLogLevelToDebug updates the DefaultLogger with the logrus.DebugLevel
func SetLogLevelToDebug() {
	slogLeveler.Set(slog.LevelDebug)
}

// PopulateLogOpts populates the logger options making sure that passed values are valid.
func PopulateLogOpts(o LogOptions, level string, format string) {
	if level != "" {
		o[LevelOpt] = level
	}

	if format != "" {
		format = strings.ToLower(format)
		switch LogFormat(format) {
		case logFormatText, logFormatJSON:
			o[FormatOpt] = format
		default:
			o[FormatOpt] = string(logFormatText)
		}
	}
}

// SetupLogging setup logger options taking into consideration the debug flag.
func SetupLogging(o LogOptions, debug bool) error {
	if debug {
		o[LevelOpt] = slog.LevelDebug.String()
	}
	initializeSlog(o, true)

	// always suppress the default logger so libraries don't print things
	slog.SetLogLoggerLevel(LevelPanic)

	// Bridge klog to slog. Note that this will open multiple pipes and fork
	// background goroutines that are not cleaned up.
	err := initializeKLog(DefaultSlogLogger)
	if err != nil {
		return err
	}

	return nil
}

// GetLogger returns the DefaultLogger that was previously setup
func GetLogger() *slog.Logger {
	return DefaultSlogLogger
}

// GetLogLevel returns the log level of the current slog.
func GetLogLevel(logger FieldLogger) slog.Level {
	ctx := context.Background()
	switch {
	case logger.Enabled(ctx, LevelTrace):
		return LevelTrace
	case logger.Enabled(ctx, slog.LevelDebug):
		return slog.LevelDebug
	case logger.Enabled(ctx, slog.LevelInfo):
		return slog.LevelInfo
	case logger.Enabled(ctx, slog.LevelWarn):
		return slog.LevelWarn
	case logger.Enabled(ctx, slog.LevelError):
		return slog.LevelError
	case logger.Enabled(ctx, LevelPanic):
		return LevelPanic
	case logger.Enabled(ctx, LevelFatal):
		return LevelFatal
	}
	return slog.LevelInfo
}

// ParseLevel takes a string level and returns the slog log level constant.
func ParseLevel(lvl string) (slog.Level, error) {
	switch strings.ToUpper(lvl) {
	case "TRACE":
		return LevelTrace, nil
	case "DEBUG":
		return slog.LevelDebug, nil
	case "INFO":
		return slog.LevelInfo, nil
	case "WARN", "WARNING":
		return slog.LevelWarn, nil
	case "ERROR":
		return slog.LevelError, nil
	case "PANIC":
		return LevelPanic, nil
	case "FATAL":
		return LevelFatal, nil
	default:
		return slog.LevelInfo, errors.New("unknown level " + lvl)
	}
}
