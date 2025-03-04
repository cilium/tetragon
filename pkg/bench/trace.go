// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package bench

import (
	"context"
	"log"
	"os"
	"strings"
	"time"
)

type TraceBench interface {
	ConfigFilename(args *Arguments) string
	Run(ctx context.Context, args *Arguments, summary *Summary) error
}

var (
	traceBenches = []string{"rw", "open", "custom"}
)

func TraceBenchSupported() []string {
	keys := make([]string, 0, len(traceBenches))
	for _, k := range traceBenches {
		keys = append(keys, string(k))
	}
	return keys
}

func TraceBenchNameOrPanic(s string) string {
	for _, k := range traceBenches {
		if k == s {
			return s
		}
	}
	log.Fatalf("Unknown bench '%s', use one of: %s", s, strings.Join(TraceBenchSupported(), ", "))
	return string("")
}

func RunTraceBench(args *Arguments) (summary *Summary) {
	ctx, cancel := context.WithCancel(context.Background())
	go sigHandler(ctx, cancel)

	summary = newSummary(args)
	summary.StartTime = time.Now()

	disable := EnableBpfStats()
	defer disable()

	oldBpfStats := GetBpfStats()

	var bench TraceBench

	switch args.Trace {
	case "rw":
		bench = newTraceBenchRw()
	case "open":
		bench = newTraceBenchOpen()
	case "custom":
		bench = newTraceBenchCustom()
	default:
		panic("unknown benchmark")
	}

	configFile := bench.ConfigFilename(args)

	if args.Trace != "custom" {
		defer os.Remove(configFile)
	}

	// Start tetragon if requested.
	tetragonFinished := make(chan bool, 1)
	if !args.Baseline {
		ready := make(chan bool)
		log.Printf("Starting tetragon...\n")
		go func() {
			runTetragon(ctx, configFile, args, summary, ready)
			tetragonFinished <- true
		}()
		// Wait for tetragon to initialize.
		<-ready
	} else {
		tetragonFinished <- true
	}
	summary.SetupDurationNanos = time.Since(summary.StartTime)

	log.Printf("Benchmark start [%s]", args.Trace)

	cpuUsageBefore := GetCPUUsage(CPU_USAGE_ALL_THREADS)

	summary.RunTime = time.Now()

	err := bench.Run(ctx, args, summary)
	if err != nil {
		cancel()
		return
	}

	summary.EndTime = time.Now()

	cpuUsageAfter := GetCPUUsage(CPU_USAGE_ALL_THREADS)

	summary.BpfStats = GetBpfStatsSince(oldBpfStats)
	summary.TestDurationNanos = summary.EndTime.Sub(summary.StartTime)

	log.Printf("Benchmark finished, cleaning..")

	// Now that the source finished, cancel the context to stop everything and collect stats.
	cancel()
	// Wait for tetragon to finish cleaning up.
	<-tetragonFinished

	summary.TetragonCPUUsage = cpuUsageAfter.Sub(cpuUsageBefore)
	return
}
