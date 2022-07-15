// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"flag"
	"log"
	"os"
	"strings"

	"github.com/cilium/tetragon/pkg/bench"
	"github.com/spf13/viper"
	"golang.org/x/sys/unix"
)

// Command-line flags
var (
	debug       *bool
	jsonEncode  *bool
	baseline    *bool
	printEvents *bool

	traceBench *string
)

func init() {
	debug = flag.Bool("debug", false, "enable debugging")
	jsonEncode = flag.Bool("json-encode", false, "JSON encode the events and measure overhead")
	baseline = flag.Bool("baseline", false, "run a baseline benchmark without tetragon")
	printEvents = flag.Bool("print", false, "print events in JSON to stdout")
	traceBench = flag.String("trace", "none", "trace benchmark to run, one of: "+strings.Join(bench.TraceBenchSupported(), ", "))
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

	args := &bench.Arguments{
		Debug:       *debug,
		JSONEncode:  *jsonEncode || *printEvents,
		PrintEvents: *printEvents,
		Baseline:    *baseline,
		Trace:       bench.TraceBenchNameOrPanic(*traceBench),
	}

	summary := bench.RunTraceBench(args)

	summary.PrettyPrint()
	if summary.Error != "" {
		os.Exit(1)
	}
}
