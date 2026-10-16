// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package program

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/tracepoint"
)

// syscallTracepointLink is a syscalls/* tracepoint link that also keeps one
// program-less perf event per CPU open for the same tracepoint.
//
// Kernels that carry 2c2b322acdcc ("tracing: perf: Fix stale head for perf
// syscall tracing") without 57918341dd19, such as 7.1.6 and some distribution
// kernels, return from perf_syscall_enter() before running the BPF program
// array when the syscall reads user memory (execve, open, write, ...) and the
// current CPU has no perf event for the tracepoint. link.Tracepoint opens a
// single perf event on CPU 0, so on those kernels the program only runs on
// CPU 0. An enabled perf event on every CPU keeps the per-CPU event list
// non-empty and the program runs everywhere again.
type syscallTracepointLink struct {
	link.Link
	events []int
}

func (l *syscallTracepointLink) Close() error {
	err := l.Link.Close()
	for _, fd := range l.events {
		unix.Close(fd)
	}
	l.events = nil
	return err
}

// attachTracepoint attaches prog to the subsys/event tracepoint. For the
// syscalls subsystem it also opens the per-CPU perf events described above.
func attachTracepoint(subsys, event string, prog *ebpf.Program) (link.Link, error) {
	lnk, err := link.Tracepoint(subsys, event, prog, nil)
	if err != nil {
		return nil, err
	}
	if subsys != "syscalls" {
		return lnk, nil
	}
	events, err := openTracepointPerCPUEvents(subsys, event)
	if err != nil {
		logger.GetLogger().Warn("failed to open per-CPU perf events, program may only run on CPU 0",
			"tracepoint", subsys+"/"+event, logfields.Error, err)
		return lnk, nil
	}
	return &syscallTracepointLink{Link: lnk, events: events}, nil
}

// openTracepointPerCPUEvents opens an enabled perf event for the tracepoint
// on every online CPU and returns their file descriptors.
func openTracepointPerCPUEvents(subsys, event string) ([]int, error) {
	traceFS, err := tracepoint.GetTraceFSPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(traceFS, "events", subsys, event, "id"))
	if err != nil {
		return nil, err
	}
	id, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parsing tracepoint id: %w", err)
	}
	ncpu, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, err
	}
	attr := unix.PerfEventAttr{
		Type:   unix.PERF_TYPE_TRACEPOINT,
		Config: id,
	}
	fds := make([]int, 0, ncpu)
	for cpu := range ncpu {
		fd, err := unix.PerfEventOpen(&attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
		if err != nil {
			if errors.Is(err, unix.ENODEV) {
				// possible but offline CPU
				continue
			}
			for _, fd := range fds {
				unix.Close(fd)
			}
			return nil, fmt.Errorf("perf_event_open on CPU %d: %w", cpu, err)
		}
		fds = append(fds, fd)
	}
	return fds, nil
}
