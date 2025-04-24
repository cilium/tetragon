// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package logger

import (
	"fmt"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

type LogFormat string

const (
	LevelOpt  = "level"
	FormatOpt = "format"

	logFormatText LogFormat = "text"
	logFormatJSON LogFormat = "json"

	defaultLogFormat LogFormat    = logFormatText
	defaultLogLevel  logrus.Level = logrus.InfoLevel
)

var (
	// DefaultLogger is the base logrus logger. It is different from the logrus
	// default to avoid external dependencies from writing out unexpectedly
	DefaultLogger = InitializeDefaultLogger()
)

// LogOptions maps configuration key-value pairs related to logging.
type LogOptions map[string]string

// InitializeDefaultLogger returns a logrus Logger with a custom text formatter.
func InitializeDefaultLogger() (logger *logrus.Logger) {
	logger = logrus.New()
	fmt, _ := getFormatter(defaultLogFormat)
	logger.SetFormatter(fmt)
	logger.SetLevel(defaultLogLevel)
	logger.SetOutput(os.Stderr)
	return
}

// getFormatter returns a configured logrus.Formatter with some specific values
// we want to have
func getFormatter(format LogFormat) (logrus.Formatter, error) {
	switch format {
	case logFormatText:
		return &logrus.TextFormatter{
			DisableColors: true,
		}, nil
	case logFormatJSON:
		return &logrus.JSONFormatter{}, nil
	default:
		return &logrus.TextFormatter{}, fmt.Errorf("invalid log format '%s'", string(format))
	}
}

func (o LogOptions) getLogLevel() (level logrus.Level) {
	l, ok := o[LevelOpt]
	if !ok {
		return defaultLogLevel
	}

	var err error
	if level, err = logrus.ParseLevel(l); err != nil {
		logrus.WithError(err).Warning("Ignoring user-configured log level")
		return defaultLogLevel
	}
	return
}

func (o LogOptions) getLogFormat() LogFormat {
	format, ok := o[FormatOpt]
	if !ok {
		return defaultLogFormat
	}

	// It was already validate with PopulateLogOpts()
	return LogFormat(strings.ToLower(format))
}

func ResetLogOutput() {
	DefaultLogger.SetOutput(os.Stderr)
}

func GetLogLevel() logrus.Level {
	return DefaultLogger.GetLevel()
}

func SetLogLevel(logLevel logrus.Level) {
	DefaultLogger.SetLevel(logLevel)
}

func setLogLevelToDebug() {
	DefaultLogger.SetLevel(logrus.DebugLevel)
}

func setLogFormat(logFormat LogFormat) {
	fmt, err := getFormatter(logFormat)
	if err != nil {
		logrus.WithError(err).Warning("Ignoring user-configured log format")
	}
	DefaultLogger.SetFormatter(fmt)
}

// PopulateLogOpts populates the logger options making sure that passed values are valid.
func PopulateLogOpts(o LogOptions, level string, format string) {
	if level != "" {
		_, err := logrus.ParseLevel(level)
		if err != nil {
			logrus.WithError(fmt.Errorf("incorrect log level '%s'", level)).Warning("Ignoring user-configured log level")
		} else {
			o[LevelOpt] = level
		}
	}

	if format != "" {
		format = strings.ToLower(format)
		switch LogFormat(format) {
		case logFormatText, logFormatJSON:
			o[FormatOpt] = format
		default:
			logrus.WithError(fmt.Errorf("incorrect log format '%s', expected 'text' or 'json'", format)).Warning("Ignoring user-configured log format")
		}
	}
}

// SetupLogging setup logger options taking into consideration the debug flag.
func SetupLogging(o LogOptions, debug bool) error {
	// Updating the default log format
	setLogFormat(o.getLogFormat())

	logrus.SetOutput(os.Stderr)

	// Updating the default log level, overriding the log options if the debug arg is being set
	if debug {
		setLogLevelToDebug()
	} else {
		SetLogLevel(o.getLogLevel())
	}

	// always suppress the default logger so libraries don't print things
	logrus.SetLevel(logrus.PanicLevel)

	return nil
}

// GetLogger returns the DefaultLogger that was previously setup
func GetLogger() logrus.FieldLogger {
	return DefaultLogger
}
