// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package bugtool

// For bugtool we want to log things into two different logs: the one used by
// tetragon, but also another one that will be saved within the bugtool tar archive. The
// log levels of these two are not always the same, so we need two different
// loggers.
//
// Currently, there are only a few functions implemented but we can add what we
// need as we go.

import (
	"fmt"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
)

// MultiLog maintains multiple loggers
type MultiLog struct {
	Logs []logger.FieldLogger
}

// MultiLogEntry maintains entries generated using a MultiLog
type MultiLogEntry struct {
	Entries []logger.FieldLogger
}

// WithField creates a new entry and adds a field to it.
func (ml *MultiLog) WithField(key string, value interface{}) *MultiLogEntry {
	entries := make([]logger.FieldLogger, 0, len(ml.Logs))
	for _, log := range ml.Logs {
		entries = append(entries, log.With(key, value))
	}
	return &MultiLogEntry{
		Entries: entries,
	}
}

// WithError adds err as a single field (using ErrorKey)
func (ml *MultiLog) WithError(err error) *MultiLogEntry {
	entries := make([]logger.FieldLogger, 0, len(ml.Logs))
	for _, log := range ml.Logs {
		entries = append(entries, log.With(logfields.Error, err))
	}
	return &MultiLogEntry{
		Entries: entries,
	}
}

func (ml *MultiLog) Info(msg string, args ...interface{}) {
	for _, log := range ml.Logs {
		log.Info(msg, args...)
	}
}

func (ml *MultiLog) Warn(msg string, args ...interface{}) {
	for _, log := range ml.Logs {
		log.Warn(msg, args...)
	}
}

func (ml *MultiLog) Warnf(format string, args ...interface{}) {
	for _, log := range ml.Logs {
		log.Warn(fmt.Sprintf(format, args...))
	}
}

func (ml *MultiLog) Infof(format string, args ...interface{}) {
	for _, log := range ml.Logs {
		log.Info(fmt.Sprintf(format, args...))
	}
}

// WithField creates a new entry by adding a field to an existing one
func (mle *MultiLogEntry) WithField(key string, value interface{}) *MultiLogEntry {
	entries := make([]logger.FieldLogger, 0, len(mle.Entries))
	for _, entry := range mle.Entries {
		entries = append(entries, entry.With(key, value))
	}
	return &MultiLogEntry{
		Entries: entries,
	}
}

// WithError adds err as a single field (using ErrorKey)
func (mle *MultiLogEntry) WithError(err error) *MultiLogEntry {
	entries := make([]logger.FieldLogger, 0, len(mle.Entries))
	for _, entry := range mle.Entries {
		entries = append(entries, entry.With(logfields.Error, err))
	}
	return &MultiLogEntry{
		Entries: entries,
	}
}

// Warn logs at the Warning level
func (mle *MultiLogEntry) Warn(msg string, args ...interface{}) {
	for _, entry := range mle.Entries {
		entry.Warn(msg, args...)
	}
}

// Info logs at the Info level
func (mle *MultiLogEntry) Info(msg string, args ...interface{}) {
	for _, entry := range mle.Entries {
		entry.Info(msg, args...)
	}
}

func (mle *MultiLogEntry) Warnf(format string, args ...interface{}) {
	for _, entry := range mle.Entries {
		entry.Warn(fmt.Sprintf(format, args...))
	}
}

func (mle *MultiLogEntry) Infof(format string, args ...interface{}) {
	for _, entry := range mle.Entries {
		entry.Info(fmt.Sprintf(format, args...))
	}
}
