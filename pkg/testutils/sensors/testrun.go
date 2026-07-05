// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"os"
	"path/filepath"
	"runtime"
	"time"
)

var config *Config

// Conf is configuration for testing sensors.
// It is intialized in TestSensorsRun() so all sensors test should call this
// function in their TestMain
type Config struct {
	TetragonLib         string
	SelfBinary          string
	CmdWaitTime         time.Duration
	DisableTetragonLogs bool
	Debug               bool
	Trace               bool
}

var ConfigDefaults = Config{
	TetragonLib: filepath.Join(TetragonBpfPath(), "objs"),
	SelfBinary:  filepath.Base(os.Args[0]),
	// NB: for sensor tests, CmdWaitTime is initialized by TestSensorsRun to 5min
	CmdWaitTime:         60000 * time.Millisecond,
	DisableTetragonLogs: false,
	Debug:               false,
	Trace:               false,
}

func Conf() *Config {
	if config == nil {
		panic("please call TestSensorsRun() to initialize GetTestSensorsConf")
	}
	return config
}

// SetConf initializes the test sensors config for callers that run outside the
// `go test` sensor harness (e.g. the `tetra policytest` CLI), so Conf() does not
// panic. TestSensorsRun() still owns initialization for sensor tests.
func SetConf(c *Config) {
	config = c
}

// TetragonBpfPath retrieves bpf code path
func TetragonBpfPath() string {
	_, testFname, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(testFname), "..", "..", "..", "bpf")
}
