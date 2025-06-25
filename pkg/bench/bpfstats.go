// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package bench

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func EnableBPFStats() func() error {
	// 5.8 and upwards have a reentrancy safe API to enable stats.
	stats, err := ebpf.EnableStats(unix.BPF_STATS_RUN_TIME)
	if err == nil {
		return stats.Close
	}

	err = os.WriteFile("/proc/sys/kernel/bpf_stats_enabled", []byte("1"), 0666)
	if err != nil {
		log.Fatalf("failed to enable bpf stats: %v", err)
	}

	return func() error {
		return os.WriteFile("/proc/sys/kernel/bpf_stats_enabled", []byte("0"), 0666)
	}
}

type BPFProgStats struct {
	ID     int64  `json:"id"`
	Type   string `json:"type"`
	Name   string `json:"name"`
	RunNs  int64  `json:"run_time_ns"`
	RunCnt int64  `json:"run_cnt"`
	// ...
}

func (bps *BPFProgStats) String() string {
	duration := time.Duration(0)
	if bps.RunCnt > 0 {
		duration = time.Duration(bps.RunNs / bps.RunCnt)
	}
	name := bps.Name
	if len(name) == 0 {
		name = "<unnamed>"
	}

	lbl := fmt.Sprintf("%-30s [%s/%d]", name, bps.Type, bps.ID)

	return fmt.Sprintf("%-50s:\t%.2fµs (%d)",
		lbl, float64(duration)/float64(time.Microsecond), bps.RunCnt)
}

func GetBPFStatsSince(oldStats map[int64]*BPFProgStats) map[int64]*BPFProgStats {
	newStats := GetBPFStats()
	for id, newStat := range newStats {
		if oldStat, ok := oldStats[id]; ok {
			newStat.RunNs -= oldStat.RunNs
			newStat.RunCnt -= oldStat.RunCnt
		}
	}
	return newStats
}

func GetBPFStats() map[int64]*BPFProgStats {
	out, err := exec.Command("/bin/sh", "-c", "bpftool prog show -j").Output()
	if err != nil {
		log.Printf("Failed to query bpf stats: %s\n", err)
		return nil
	}

	var stats []BPFProgStats
	err = json.Unmarshal(out, &stats)
	if err != nil {
		log.Printf("Failed to parse bpf stats: %s\n", err)
		return nil
	}

	m := make(map[int64]*BPFProgStats)
	for id := range stats {
		var s = &stats[id]
		m[s.ID] = s
	}
	return m
}
