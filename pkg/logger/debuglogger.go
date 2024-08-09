// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package logger

import (
	"fmt"
	"io"
	"runtime"

	"github.com/sirupsen/logrus"
)

// there is no way to have selective information level  per sub-system
// (see: https://github.com/cilium/cilium/issues/21002) so we define
// a utility type here

func initEmptylogger() logrus.FieldLogger {
	// NB: we could define a better empty logger, that also ignores WithField
	log := logrus.New()
	log.SetOutput(io.Discard)
	return log
}

var (
	emptyLogger = initEmptylogger()
)

type DebugLogger struct {
	logger       logrus.FieldLogger
	debugEnabled bool
}

func NewDebugLogger(logger logrus.FieldLogger, debugEnabled bool) *DebugLogger {
	return &DebugLogger{
		logger:       logger,
		debugEnabled: debugEnabled,
	}
}

func (d *DebugLogger) DebugLogWithCallers(nCallers int) logrus.FieldLogger {
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
		log = log.WithField(key, fn.Name())
	}

	return log
}

func (d *DebugLogger) Debug(args ...interface{}) {
	if d.debugEnabled {
		d.logger.Info(args...)
	} else {
		d.logger.Debug(args...)
	}
}

func (d *DebugLogger) Debugf(fmt string, args ...interface{}) {
	if d.debugEnabled {
		d.logger.Infof(fmt, args...)
	} else {
		d.logger.Debugf(fmt, args...)
	}
}
