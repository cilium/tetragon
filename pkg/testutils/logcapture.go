// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package testutils

import (
	"io"
	"testing"

	tus "github.com/cilium/tetragon/pkg/testutils/sensors"

	"github.com/sirupsen/logrus"
)

type LogCapturer struct {
	*testing.T
	Log *logrus.Logger
}

func (tl LogCapturer) Write(p []byte) (n int, err error) {
	tl.Logf((string)(p))
	return len(p), nil
}

// CaptureLog redirects logrus output to testing.Log
func CaptureLog(t *testing.T, l *logrus.Logger) {
	lc := &LogCapturer{
		T:   t,
		Log: l,
	}

	origOut := logrus.StandardLogger().Out
	t.Cleanup(func() {
		l.SetOutput(origOut)
	})

	if tus.Conf().DisableTetragonLogs {
		l.SetOutput(io.Discard)
	} else {
		l.SetOutput(lc)
	}
}
