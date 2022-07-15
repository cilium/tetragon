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
	log     *logrus.Logger
}

func (tl logCapturer) Write(p []byte) (n int, err error) {
	tl.Logf((string)(p))
	return len(p), nil
}

func (tl logCapturer) Release() {
	tl.log.SetOutput(tl.origOut)
}

// CaptureLog redirects logrus output to testing.Log
func captureLog(t *testing.T, l *logrus.Logger) *logCapturer {
	lc := &logCapturer{
		T:       t,
		origOut: logrus.StandardLogger().Out,
		log:     l,
	}
	if !testing.Verbose() {
		l.SetOutput(lc)
	}
	return lc
}
