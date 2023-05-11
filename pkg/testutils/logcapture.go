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
	*testing.T
	Log *logrus.Logger
}

func (tl LogCapturer) Write(p []byte) (n int, err error) {
	// Since we are calling T.Log() here, we want to avoid appending multiple "\n", so
	// trim whatever was added by the inner logger.
	s := strings.TrimRight(string(p), "\n")
	tl.T.Log(s)
	return len(s), nil
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
