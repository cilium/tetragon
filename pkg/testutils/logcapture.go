// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package testutils

import (
	"io"
	"testing"

	"github.com/sirupsen/logrus"
)

type LogCapturer struct {
	*testing.T
	OrigOut io.Writer
	Log     *logrus.Logger
}

func (tl LogCapturer) Write(p []byte) (n int, err error) {
	tl.Logf((string)(p))
	return len(p), nil
}

func (tl LogCapturer) Release() {
	tl.Log.SetOutput(tl.OrigOut)
}

// CaptureLog redirects logrus output to testing.Log
func CaptureLog(t *testing.T, l *logrus.Logger) *LogCapturer {
	lc := &LogCapturer{
		T:       t,
		OrigOut: logrus.StandardLogger().Out,
		Log:     l,
	}
	if !testing.Verbose() {
		l.SetOutput(lc)
	}
	return lc
}
