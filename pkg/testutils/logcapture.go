// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package testutils

import (
	"io"
	"strings"
	"testing"

	tus "github.com/cilium/tetragon/pkg/testutils/sensors"

	"github.com/sirupsen/logrus"
)

type LogCapturer struct {
	TB  testing.TB
	Log *logrus.Logger
}

func (tl LogCapturer) Write(p []byte) (n int, err error) {
	// Since we are calling T.Log() here, we want to avoid appending multiple "\n", so
	// trim whatever was added by the inner logger.
	s := strings.TrimRight(string(p), "\n")
	tl.TB.Log(s)
	return len(s), nil
}

// CaptureLog redirects logrus output to testing.Log
func CaptureLog(tb testing.TB, l *logrus.Logger) {
	lc := &LogCapturer{
		TB:  tb,
		Log: l,
	}

	origOut := logrus.StandardLogger().Out
	tb.Cleanup(func() {
		l.SetOutput(origOut)
	})

	if tus.Conf().DisableTetragonLogs {
		l.SetOutput(io.Discard)
	} else {
		l.SetOutput(lc)
	}
}
