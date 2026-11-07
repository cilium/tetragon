// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package ktime

import (
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/config"
)

func NanoTimeSince(ktime int64) (time.Duration, error) {
	clk := bpfClock()
	currentTime := unix.Timespec{}
	if err := unix.ClockGettime(clk, &currentTime); err != nil {
		return 0, err
	}
	diff := currentTime.Nano() - ktime
	return time.Duration(diff), nil
}

// Now returns the current time on the clock BPF programs stamp ktimes with.
func Now() (time.Duration, error) {
	clk := bpfClock()
	currentTime := unix.Timespec{}
	if err := unix.ClockGettime(clk, &currentTime); err != nil {
		return 0, err
	}
	return time.Duration(currentTime.Nano()), nil
}

// DecodeKtime converts ktime to wall-clock time. fromBPF reports whether a
// BPF program stamped ktime; otherwise ktime is CLOCK_BOOTTIME, the clock of
// procfs start times.
func DecodeKtime(ktime int64, fromBPF bool) (time.Time, error) {
	clk := int32(unix.CLOCK_BOOTTIME)
	if fromBPF {
		clk = bpfClock()
	}
	currentTime := unix.Timespec{}
	if err := unix.ClockGettime(clk, &currentTime); err != nil {
		return time.Time{}, err
	}
	diff := ktime - currentTime.Nano()
	t := time.Now().Add(time.Duration(diff))
	return t, nil
}

// bpfClock is the clock tg_get_ktime() (bpf/include/bpf_ktime.h) reads:
// CLOCK_BOOTTIME in large programs on kernels with bpf_ktime_get_boot_ns(),
// CLOCK_MONOTONIC otherwise.
var bpfClock = sync.OnceValue(func() int32 {
	if config.EnableLargeProgs() && bpf.HasKtimeGetBootNs() {
		return unix.CLOCK_BOOTTIME
	}
	return unix.CLOCK_MONOTONIC
})
