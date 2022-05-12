// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package bugtool

// For bugtool we want to log things into two different logs: the one used by
// tetragon, but also another one that will be saved within the bugtool tar archive. The
// log levels of these two are not always the same, so we need two different
// loggers.
//
// We also keep both generated Entries in a new MultiLogEntry structure. This
// means that we cannot implement the logrus.FileLogger interface
// (https://godoc.org/github.com/sirupsen/logrus#FieldLogger), but we can have
// similar functions that use MultiLogEntry instead of Entry.
//
// Currently, there are only a few functions implemented but we can add what we
// need as we go.

import (
	"github.com/sirupsen/logrus"
)

// MultiLog maintains multiple loggers
type MultiLog struct {
	Logs []logrus.FieldLogger
}

// MultiLogEntry maintains entries generated using a MultiLog
type MultiLogEntry struct {
	Entries []*logrus.Entry
}

// WithField creates a new entry and adds a field to it.
func (ml *MultiLog) WithField(key string, value interface{}) *MultiLogEntry {
	entries := make([]*logrus.Entry, 0, len(ml.Logs))
	for _, log := range ml.Logs {
		entries = append(entries, log.WithField(key, value))
	}
	return &MultiLogEntry{
		Entries: entries,
	}
}

// WithError adds err as a single field (using ErrorKey)
func (ml *MultiLog) WithError(err error) *MultiLogEntry {
	entries := make([]*logrus.Entry, 0, len(ml.Logs))
	for _, log := range ml.Logs {
		entries = append(entries, log.WithError(err))
	}
	return &MultiLogEntry{
		Entries: entries,
	}
}

func (ml *MultiLog) Info(args ...interface{}) {
	for _, log := range ml.Logs {
		log.Info(args...)
	}
}

func (ml *MultiLog) Warn(args ...interface{}) {
	for _, log := range ml.Logs {
		log.Warn(args...)
	}
}

func (ml *MultiLog) Warnf(format string, args ...interface{}) {
	for _, log := range ml.Logs {
		log.Warnf(format, args...)
	}
}

func (ml *MultiLog) Infof(format string, args ...interface{}) {
	for _, log := range ml.Logs {
		log.Infof(format, args...)
	}
}

// WithField creates a new entry by adding a field to an existing one
func (mle *MultiLogEntry) WithField(key string, value interface{}) *MultiLogEntry {
	entries := make([]*logrus.Entry, 0, len(mle.Entries))
	for _, entry := range mle.Entries {
		entries = append(entries, entry.WithField(key, value))
	}
	return &MultiLogEntry{
		Entries: entries,
	}
}

// WithError adds err as a single field (using ErrorKey)
func (mle *MultiLogEntry) WithError(err error) *MultiLogEntry {
	entries := make([]*logrus.Entry, 0, len(mle.Entries))
	for _, entry := range mle.Entries {
		entries = append(entries, entry.WithError(err))
	}
	return &MultiLogEntry{
		Entries: entries,
	}
}

// Warn logs at the Warning level
func (mle *MultiLogEntry) Warn(args ...interface{}) {
	for _, entry := range mle.Entries {
		entry.Warn(args...)
	}
}

// Info logs at the Info level
func (mle *MultiLogEntry) Info(args ...interface{}) {
	for _, entry := range mle.Entries {
		entry.Info(args...)
	}
}

func (mle *MultiLogEntry) Warnf(format string, args ...interface{}) {
	for _, entry := range mle.Entries {
		entry.Warnf(format, args...)
	}
}

func (mle *MultiLogEntry) Infof(format string, args ...interface{}) {
	for _, entry := range mle.Entries {
		entry.Infof(format, args...)
	}
}
