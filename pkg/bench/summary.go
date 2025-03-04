// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package bench

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/cilium/tetragon/pkg/metrics/kprobemetrics"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/fatih/color"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// Summary gathers benchmark results. Serializes to JSON.
// This is updated from multiple places concurrently (ExportStats
// are from tetragon process), but currently there is no overlap on
// writes, so this isn't yet protected by a mutex.
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

	TetragonCPUUsage CPUUsage

	// key is the bpf program id
	BpfStats map[int64]*BpfProgStats

	Error string
}

func (s *Summary) Dump() {
	err := json.NewEncoder(os.Stdout).Encode(s)
	if err != nil {
		log.Fatalf("json.Encode: %v", err)
	}
}

func getCounterValue(counter prometheus.Counter) int {
	var d dto.Metric
	counter.Write(&d)
	return int(*d.Counter.Value)
}

func (s *Summary) PrettyPrint() {
	color.Set(color.FgBlue)
	fmt.Println("Benchmark summary")
	fmt.Println("-----------------")
	color.Unset()
	fmt.Printf("Test started:       %s\n", s.StartTime)
	fmt.Printf("Test ended:         %s\n", s.EndTime)
	fmt.Printf("Workload start:     %s\n", s.EndTime)
	fmt.Printf("Arguments:          %v\n", s.Args)
	fmt.Printf("Total duration:     %s\n", s.EndTime.Sub(s.StartTime))
	fmt.Printf("Setup duration:     %s\n", s.SetupDurationNanos)
	fmt.Printf("Workload duration:  %s\n", s.EndTime.Sub(s.RunTime))
	fmt.Printf("Test duration:      %s\n", s.TestDurationNanos)
	fmt.Printf("Export duration:    %s\n", s.JSONEncodingDurationNanos)
	fmt.Printf("Export stats:       %s\n", s.ExportStats.String())
	fmt.Printf("Tetragon cpu usage: %s\n", s.TetragonCPUUsage)

	if !s.Args.Baseline {
		fmt.Printf("Ring buffer:        received=%d, lost=%d, errors=%d\n",
			getCounterValue(observer.RingbufReceived),
			getCounterValue(observer.RingbufLost),
			getCounterValue(observer.RingbufErrors))

		mergePushed := getCounterValue(kprobemetrics.MergePushed)
		mergeOkTotal := getCounterValue(kprobemetrics.MergeOkTotal)
		fmt.Printf("Merged events:      pushed=%d, ok=%d, errors=%d\n",
			mergePushed, mergeOkTotal, mergePushed-mergeOkTotal)
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

func (s *Summary) CSVPrint(path, name string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)

	records := [][]string{
		{"Name", name},
		{"Workload duration",
			fmt.Sprintf("%v", s.EndTime.Sub(s.RunTime)),
			fmt.Sprintf("%d", s.EndTime.Sub(s.RunTime)),
		},
		{"Tetragon SystemTime",
			fmt.Sprintf("%v", s.TetragonCPUUsage.SystemTime),
			fmt.Sprintf("%d", s.TetragonCPUUsage.SystemTime),
		},
		{"Tetragon UserTime",
			fmt.Sprintf("%v", s.TetragonCPUUsage.UserTime),
			fmt.Sprintf("%d", s.TetragonCPUUsage.UserTime),
		},
		{"Tetragon MaxRss", fmt.Sprintf("%d", s.TetragonCPUUsage.MaxRss)},
		{"Tetragon ContextSwitches", fmt.Sprintf("%d", s.TetragonCPUUsage.ContextSwitches)},
	}
	w.WriteAll(records)

	if !s.Args.Baseline {
		records = [][]string{
			{"Received", fmt.Sprintf("%d", getCounterValue(observer.RingbufReceived))},
			{"Lost", fmt.Sprintf("%d", getCounterValue(observer.RingbufLost))},
			{"Errors", fmt.Sprintf("%d", getCounterValue(observer.RingbufErrors))},
		}
		w.WriteAll(records)
	}
	return w.Error()
}
