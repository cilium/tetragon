// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package eventchecker

//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//

import (
	"testing"

	"github.com/sirupsen/logrus"
)

// Logger interface to be used in checkers
type Logger interface {
	Log(args ...interface{})
	Logf(format string, args ...interface{})
	Fatal(args ...interface{})
	Fatalf(format string, args ...interface{})
}

// PrefixLogger is a simple wrapper of Logger that allows to log with a prefix
type PrefixLogger struct {
	Prefix string
	Logger Logger
}

// Log logs a new message at the INFO level
func (l *PrefixLogger) Log(args ...interface{}) {
	if t, ok := l.Logger.(*testing.T); ok {
		t.Helper()
	}
	newargs := append([]interface{}{l.Prefix}, args...)
	l.Logger.Log(newargs...)
}

// Fatal logs a new message at the FATAL level
func (l *PrefixLogger) Fatal(args ...interface{}) {
	if t, ok := l.Logger.(*testing.T); ok {
		t.Helper()
	}
	newargs := append([]interface{}{l.Prefix}, args...)
	l.Logger.Fatal(newargs...)
}

// Logf logs a new message at the INFO level using a format string
func (l *PrefixLogger) Logf(format string, args ...interface{}) {
	if t, ok := l.Logger.(*testing.T); ok {
		t.Helper()
	}
	newfmt := "%s" + format
	newargs := append([]interface{}{l.Prefix}, args...)
	l.Logger.Logf(newfmt, newargs...)
}

// Fatalf logs a new message at the FATL level using a format string
func (l *PrefixLogger) Fatalf(format string, args ...interface{}) {
	if t, ok := l.Logger.(*testing.T); ok {
		t.Helper()
	}
	newfmt := "%s" + format
	newargs := append([]interface{}{l.Prefix}, args...)
	l.Logger.Fatalf(newfmt, newargs...)
}

// LogrusLogger wraps a logrus logger
type LogrusLogger struct {
	L *logrus.Logger
}

// Log wraps the logrus Log method
func (l *LogrusLogger) Log(args ...interface{}) {
	l.L.Log(logrus.InfoLevel, args...)
}

// Fatal wraps the logrus Fatal method
func (l *LogrusLogger) Fatal(args ...interface{}) {
	l.L.Fatal(args...)
}

// Logf wraps the logrus Logf method
func (l *LogrusLogger) Logf(format string, args ...interface{}) {
	l.L.Logf(logrus.InfoLevel, format, args...)
}

// Fatalf wraps the logrus Fatalf method
func (l *LogrusLogger) Fatalf(format string, args ...interface{}) {
	l.L.Fatalf(format, args...)
}
