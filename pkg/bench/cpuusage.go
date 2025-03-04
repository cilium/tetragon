// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package bench

import (
	"fmt"
	"log"
	"syscall"
	"time"
)

type CPUUsage struct {
	SystemTime      time.Duration
	UserTime        time.Duration
	MaxRss          int64
	ContextSwitches int64
}

type CPUUsageTarget int

const (
	CPU_USAGE_ALL_THREADS = syscall.RUSAGE_SELF
	CPU_USAGE_THIS_THREAD = syscall.RUSAGE_THREAD
)

func CPUUsageFromRusage(rusage *syscall.Rusage) (cpuUsage CPUUsage) {
	cpuUsage.UserTime = timevalToDuration(rusage.Utime)
	cpuUsage.SystemTime = timevalToDuration(rusage.Stime)
	cpuUsage.MaxRss = rusage.Maxrss
	cpuUsage.ContextSwitches = rusage.Nivcsw + rusage.Nvcsw
	return
}

func GetCPUUsage(tgt CPUUsageTarget) CPUUsage {
	var rusage syscall.Rusage
	if err := syscall.Getrusage(int(tgt), &rusage); err != nil {
		log.Printf("Getrusage failed: %v", err)
		return CPUUsage{}
	}
	return CPUUsageFromRusage(&rusage)
}

func timevalToDuration(tv syscall.Timeval) time.Duration {
	return time.Duration(tv.Sec)*time.Second +
		time.Duration(tv.Usec)*time.Microsecond
}

func (cu CPUUsage) Sub(cu2 CPUUsage) CPUUsage {
	cu.UserTime -= cu2.UserTime
	cu.SystemTime -= cu2.SystemTime
	cu.ContextSwitches -= cu2.ContextSwitches
	return cu
}

func (cu CPUUsage) Add(cu2 CPUUsage) CPUUsage {
	cu.UserTime += cu2.UserTime
	cu.SystemTime += cu2.SystemTime
	cu.ContextSwitches += cu2.ContextSwitches
	return cu
}

func (cu CPUUsage) String() string {
	return fmt.Sprintf("system=%s, user=%s, rss=%d, ctxsw=%d", cu.SystemTime, cu.UserTime, cu.MaxRss, cu.ContextSwitches)
}
