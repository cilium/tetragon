// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package bench

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/cilium/tetragon/pkg/metrics/ringbufmetrics"
	"github.com/fatih/color"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// Summary gathers benchmark results. Serializes to JSON.
// This is updated from multiple places concurrently, but currently
// there is no overlap on writes, so this isn't yet protected by a mutex.
type Summary struct {
	Args *Arguments

	ExitEvents, ExecEvents int64

	StartTime          time.Time
	EndTime            time.Time
	RunTime            time.Time
	SetupDurationNanos time.Duration
	TestDurationNanos  time.Duration

	JSONEncodingDurationNanos time.Duration
	ExportStats               CountingDiscardWriter

	FgsCPUUsage CPUUsage

	BpfStats map[int64]*BpfProgStats

	Error string
}

func (s *Summary) Dump() {
	err := json.NewEncoder(os.Stdout).Encode(s)
	if err != nil {
		log.Fatalf("json.Encode: %v", err)
	}
}

func getGaugeValue(gauge prometheus.Gauge) int {
	// Yep, this does seem to be the only way to read it.
	var d dto.Metric
	gauge.Write(&d)
	return int(*d.Gauge.Value)
}

func (s *Summary) PrettyPrint() {
	color.Set(color.FgBlue)
	fmt.Println("Benchmark summary")
	fmt.Println("-----------------")
	color.Unset()
	fmt.Printf("Test started:      %s\n", s.StartTime)
	fmt.Printf("Test ended:        %s\n", s.EndTime)
	fmt.Printf("Workload start:    %s\n", s.EndTime)
	fmt.Printf("Arguments:         %v\n", s.Args)
	fmt.Printf("Total duration:    %s\n", s.EndTime.Sub(s.StartTime))
	fmt.Printf("Setup duration:    %s\n", s.SetupDurationNanos)
	fmt.Printf("Workload duration: %s\n", s.EndTime.Sub(s.RunTime))
	fmt.Printf("Test duration:     %s\n", s.TestDurationNanos)
	fmt.Printf("Export duration:   %s\n", s.JSONEncodingDurationNanos)
	fmt.Printf("Export stats:      %s\n", s.ExportStats.String())
	fmt.Printf("FGS cpu usage:     %s\n", s.FgsCPUUsage)

	if !s.Args.Baseline {
		fmt.Printf("Ring buffer:       received=%d, lost=%d, errors=%d\n",
			getGaugeValue(ringbufmetrics.PerfEventReceived.WithLabelValues()),
			getGaugeValue(ringbufmetrics.PerfEventLost.WithLabelValues()),
			getGaugeValue(ringbufmetrics.PerfEventErrors.WithLabelValues()))
	}

	fmt.Println("BPF statistics:")
	for _, bps := range s.BpfStats {
		if bps.RunCnt > 0 {
			fmt.Printf("  %s\n", bps)
		}
	}

	if s.Error != "" {
		color.Set(color.FgRed)
		fmt.Printf("Error:             %s\n", s.Error)
		color.Unset()
	}
}

func (s *Summary) WriteFile(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(s)
}

func newSummary(args *Arguments) *Summary {
	return &Summary{
		StartTime: time.Now(),
		Args:      args,
	}
}
