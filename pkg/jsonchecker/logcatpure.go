// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package jsonchecker

import (
	"io"
	"testing"

	"github.com/sirupsen/logrus"
)

type logCapturer struct {
	*testing.T
	origOut io.Writer
}

func (tl logCapturer) Write(p []byte) (n int, err error) {
	tl.Logf((string)(p))
	return len(p), nil
}

func (tl logCapturer) Release() {
	logrus.SetOutput(tl.origOut)
}

// CaptureLog redirects logrus output to testing.Log
func captureLog(t *testing.T) *logCapturer {
	lc := &logCapturer{T: t, origOut: logrus.StandardLogger().Out}
	if !testing.Verbose() {
		logrus.SetOutput(lc)
	}
	return lc
}
