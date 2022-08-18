// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package sensors

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

var config *Config

// Conf is configuration for testing sensors.
// It is intialized in TestSensorsRun() so all sensors test should call this
// function in their TestMain
type Config struct {
	TetragonLib         string
	VerboseLevel        int
	SelfBinary          string
	CmdWaitTime         time.Duration
	DisableTetragonLogs bool
	Debug               bool
}

var ConfigDefaults = Config{
	TetragonLib:         filepath.Join(TetragonBpfPath(), "objs"),
	VerboseLevel:        0,
	SelfBinary:          filepath.Base(os.Args[0]),
	CmdWaitTime:         60000 * time.Millisecond,
	DisableTetragonLogs: false,
	Debug:               false,
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
	flag.IntVar(
		&config.VerboseLevel,
		"verbosity-level",
		ConfigDefaults.VerboseLevel,
		"verbosity level of verbose mode. (Requires verbose mode to be enabled.)")
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
	flag.Parse()

	if config.Debug {
		if err := logger.SetupLogging(option.Config.LogOpts, true); err != nil {
			log.Fatal(err)
		}
	}

	// use a sensor-specific name for the bpffs directory for the maps.
	// Also, we currently seem to fail to remove the /sys/fs/bpf/<testMapDir>
	// Do so here, until we figure out a way to do it properly. Also, issue
	// a message.
	testMapDir := fmt.Sprintf("test%s", sensorName)

	bpf.CheckOrMountFS("")
	bpf.CheckOrMountDebugFS()
	bpf.ConfigureResourceLimits()

	bpf.SetMapPrefix(testMapDir)
	defer func() {
		path := bpf.MapPrefixPath()
		_, err := os.Stat(path)
		if os.IsNotExist(err) {
			return
		}
		fmt.Printf("map dir `%s` still exists after test. Removing it.\n", path)
		os.RemoveAll(path)
	}()
	if err := btf.InitCachedBTF(context.Background(), config.TetragonLib, ""); err != nil {
		fmt.Printf("InitCachedBTF failed: %v", err)
	}
	return m.Run()
}
