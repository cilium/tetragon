// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"os"
	"testing"

	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
)

func TestMain(m *testing.M) {
	ec := tus.TestSensorsRun(m, "SensorTracing")
	os.Exit(ec)
}
