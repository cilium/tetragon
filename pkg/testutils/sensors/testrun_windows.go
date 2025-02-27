// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/sirupsen/logrus"
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

// TetragonBpfPath retrieves bpf code path
func TetragonBpfPath() string {
	_, testFname, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(testFname), "..", "..", "..", "bpf")
}

func TestSensorsRun(m *testing.M, sensorName string) int {
	c := ConfigDefaults
	config = &c

	// instruct loader to keep the loaded collection for TestLoad* tests
	program.KeepCollection = true

	// some tests require the name of the current binary.
	config.SelfBinary = filepath.Base(os.Args[0])

	flag.StringVar(&config.TetragonLib,
		"bpf-lib", ConfigDefaults.TetragonLib,
		"tetragon lib directory (location of btf file and bpf objs). Will be overridden by an TETRAGON_LIB env variable.")
	flag.DurationVar(&config.CmdWaitTime,
		"command-wait",
		5*time.Minute,
		"duration to wait for tetragon to gather logs from commands")
	flag.BoolVar(
		&config.DisableTetragonLogs,
		"disable-tetragon-logs",
		ConfigDefaults.DisableTetragonLogs,
		"do not output teragon log")
	flag.BoolVar(
		&config.Debug,
		"debug",
		ConfigDefaults.Debug,
		"enable debug log output")
	flag.BoolVar(
		&config.Trace,
		"trace",
		ConfigDefaults.Trace,
		"enable trace log output. Implies debug. Note that due to a naming conflict this must be passed after -args")
	flag.Parse()

	if config.Debug {
		if err := logger.SetupLogging(option.Config.LogOpts, true); err != nil {
			log.Fatal(err)
		}
	}
	if config.Trace {
		logger.DefaultLogger.SetLevel(logrus.TraceLevel)
	}

	// use a sensor-specific name for the bpffs directory for the maps.
	// Also, we currently seem to fail to remove the /sys/fs/bpf/<testMapDir>
	// Do so here, until we figure out a way to do it properly. Also, issue
	// a message.
	testMapDir := fmt.Sprintf("test%s", sensorName)

	bpf.CheckOrMountFS("")
	bpf.CheckOrMountDebugFS()
	bpf.ConfigureResourceLimits()

	if config.TetragonLib != "" {
		option.Config.HubbleLib = config.TetragonLib
	}

	bpf.SetMapPrefix(testMapDir)
	defer func() {
		log := logger.GetLogger()
		path := bpf.MapPrefixPath()
		_, err := os.Stat(path)
		if os.IsNotExist(err) {
			return
		}

		if entries, err := os.ReadDir(path); err == nil {
			for _, entry := range entries {
				log.Printf("`%s` still exists after test", entry.Name())
			}
		}

		log.Printf("map dir `%s` still exists after test. Removing it.", path)
		os.RemoveAll(path)
	}()
	return m.Run()
}
