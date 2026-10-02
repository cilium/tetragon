// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package logger

import (
	"fmt"
	"log/slog"
	"runtime"
)

// there is no way to have selective information level  per sub-system
// (see: https://github.com/cilium/cilium/issues/21002) so we define
// a utility type here

func initEmptylogger() FieldLogger {
	// NB: we could define a better empty logger, that also ignores WithField
	return slog.New(SlogNopHandler)
}

var (
	emptyLogger = initEmptylogger()
)

type DebugLogger struct {
	logger       *slog.Logger
	debugEnabled bool
}

func NewDebugLogger(logger *slog.Logger, debugEnabled bool) *DebugLogger {
	return &DebugLogger{
		logger:       logger,
		debugEnabled: debugEnabled,
	}
}

func (d *DebugLogger) DebugLogWithCallers(nCallers int) FieldLogger {
	if !d.debugEnabled {
		return emptyLogger
	}

	log := d.logger
	for i := 1; i <= nCallers; i++ {
		pc, _, _, ok := runtime.Caller(i)
		if !ok {
			return log
		}
		fn := runtime.FuncForPC(pc)
		key := fmt.Sprintf("caller-%d", i)
		log = log.With(key, fn.Name())
	}

	return log
}

func (d *DebugLogger) Debug(msg string, args ...any) {
	if d.debugEnabled {
		d.logger.Info(msg, args...)
	} else {
		d.logger.Debug(msg, args...)
	}
}

func (d *DebugLogger) Debugf(format string, args ...any) {
	if d.debugEnabled {
		d.logger.Info(fmt.Sprintf(format, args...))
	} else {
		d.logger.Debug(fmt.Sprintf(format, args...))
	}
}
