// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package testutils

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/cilium/tetragon/pkg/logger"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
)

type LogCapturer struct {
	TB  testing.TB
	Log *slog.Logger
}

func (tl LogCapturer) Write(p []byte) (n int, err error) {
	// Since we are calling T.Log() here, we want to avoid appending multiple "\n", so
	// trim whatever was added by the inner logger.
	s := strings.TrimRight(string(p), "\n")
	tl.TB.Log(s)
	return len(s), nil
}

// CaptureLog redirects slog output to testing.Log
func CaptureLog(tb testing.TB, l *slog.Logger) {
	lc := &LogCapturer{
		TB:  tb,
		Log: l,
	}

	originalLogger := logger.DefaultSlogLogger

	tb.Cleanup(func() {
		logger.DefaultSlogLogger = originalLogger
	})

	if tus.Conf().DisableTetragonLogs {
		newLogger := slog.New(logger.SlogNopHandler)
		logger.DefaultSlogLogger = newLogger
	} else {
		newLogger := slog.New(slog.NewTextHandler(lc, nil))
		logger.DefaultSlogLogger = newLogger
	}
}
