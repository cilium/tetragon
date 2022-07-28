// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"flag"
	"log"
	"os"
	"runtime/pprof"
	"strings"
	"time"

	"github.com/cilium/tetragon/pkg/bench"
	"github.com/spf13/viper"
	"golang.org/x/sys/unix"

	"github.com/tezc/goperf"
)

// Command-line flags
var (
	duration    *time.Duration
	debug       *bool
	jsonEncode  *bool
	baseline    *bool
	printEvents *bool
	goPerf      *bool

	traceBench *string
	cpuProfile *string
)

func init() {
	duration = flag.Duration("duration", 10*time.Second, "test duration")
	debug = flag.Bool("debug", false, "enable FGS debugging")
	jsonEncode = flag.Bool("json-encode", false, "JSON encode the events and measure overhead")
	baseline = flag.Bool("baseline", false, "run a baseline benchmark without FGS")
	printEvents = flag.Bool("print", false, "print events in JSON to stdout")
	traceBench = flag.String("trace", "none", "trace benchmark to run, one of: "+strings.Join(bench.TraceBenchSupported(), ", "))
	goPerf = flag.Bool("goperf", false, "Measure perf events (goperf)")
	cpuProfile = flag.String("cpuprofile", "", "start cpu prifiling to provided file")
}

func main() {
	if unix.Getuid() != 0 {
		log.Fatalf("You need to run fgs-bench as root.")
	}

	flag.Parse()
	log.SetOutput(os.Stderr)

	if *debug {
		viper.Set("log-level", "debug")
	}

	if *cpuProfile != "" {
		f, err := os.Create(*cpuProfile)
		if err != nil {
			log.Fatal("could not create CPU profile: ", err)
		}
		defer f.Close()

		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal("could not start CPU profile: ", err)
		}
		log.Printf("Starting cpu profiling: %s", *cpuProfile)
		defer func() {
			log.Printf("Stopping cpu profiling: %s", *cpuProfile)
			pprof.StopCPUProfile()
		}()
	}

	args := &bench.Arguments{
		Debug:       *debug,
		JSONEncode:  *jsonEncode || *printEvents,
		PrintEvents: *printEvents,
		Baseline:    *baseline,
		Trace:       bench.TraceBenchNameOrPanic(*traceBench),
		GoPerf:      *goPerf,
	}

	summary := bench.RunTraceBench(args)

	summary.PrettyPrint()

	if args.GoPerf {
		goperf.End()
	}

	if summary.Error != "" {
		os.Exit(1)
	}
}
