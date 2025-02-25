// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

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
	storeEvents *bool

	traceBench *string
	crd        *string
	csv        *string
	name       *string

	rbSize *int
)

func init() {
	rbSize = flag.Int("rb-size", 65535, "perf ring buffer size")
	debug = flag.Bool("debug", false, "enable debugging")
	jsonEncode = flag.Bool("json-encode", false, "JSON encode the events and measure overhead")
	baseline = flag.Bool("baseline", false, "run a baseline benchmark without tetragon")
	printEvents = flag.Bool("print", false, "print events in JSON to stdout")
	storeEvents = flag.Bool("store", false, "store events in JSON to stdout")
	traceBench = flag.String("trace", "none", "trace benchmark to run, one of: "+strings.Join(bench.TraceBenchSupported(), ", "))
	crd = flag.String("crd", "none", "crd to start tetragon with")
	csv = flag.String("csv", "none", "store stats to CSV file")
	name = flag.String("name", "", "benchmark name")
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

	var cmdArgs []string

	if *crd != "none" {
		var idx int
		var found bool

		if *traceBench != "none" {
			log.Fatalf("You can't mix -trace and -crd options.")
		}

		// find custom program to run
		for _, a := range os.Args {
			if a == "--" {
				found = true
				idx++
				break
			}
			idx++
		}

		if !found || idx == len(os.Args) {
			log.Fatalf("command not specified")
		}

		cmdArgs = os.Args[idx:]
		*traceBench = "custom"
	}

	if *printEvents && *storeEvents {
		log.Fatalf("Can't specify together -print and -store options.")
	}

	args := &bench.Arguments{
		Debug:       *debug,
		JSONEncode:  *jsonEncode || *printEvents || *storeEvents,
		PrintEvents: *printEvents,
		StoreEvents: *storeEvents,
		Baseline:    *baseline,
		Trace:       bench.TraceBenchNameOrPanic(*traceBench),
		Crd:         *crd,
		CmdArgs:     cmdArgs,
		RBSize:      *rbSize,
	}

	summary := bench.RunTraceBench(args)

	if *csv != "none" {
		summary.CSVPrint(*csv, *name)
	}

	summary.PrettyPrint()
	if summary.Error != "" {
		os.Exit(1)
	}
}
