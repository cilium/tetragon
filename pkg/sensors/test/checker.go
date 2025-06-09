// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package test

import (
	"log/slog"
	"os/exec"
	"runtime"
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/testutils"
)

//revive:disable

// TestEventChecker is a checker that relies on:
//   - the test sensor being loaded
//   - user-space executing hooks that trigger the test sensor on all cores
//     (see contrib/tester-progs/trigger-test-events).
//
// The typical structure of a test is:
//  1. start observer
//  2. do some things on user-space
//  3. check that we get the expected events from tetragon
//
// In such a test there is no way to determine when to stop looking for events.  Hence, we retry
// step 3 a number of times to gain confidence that all events from step 2 have been processed.
// These retries induce a significant time cost in failing tests or in tests that check the absence
// of events (e.g., when doing filtering).
//
// TestEventChecker enables testing without timeouts. Timeouts are still used for robustness, but
// assuming TestEventChecker works correctly they are not needed.
//
// After step 2, we trigger the hook of the test sensor (a simple sensor that generates test events)
// on all CPUs. Once we have seen all the test events (on all CPUs), then we know that if we expect
// any events, they are not there because events cannot be reordered on the same CPU.
type TestEventChecker struct {
	// eventChecker is the underlying event checker
	eventChecker      ec.MultiEventChecker
	completionChecker *CompletionChecker
}

// TestCheckerMarkEnd executes the necessary operations to mark the end of event stream on all CPUs
func TestCheckerMarkEnd(t *testing.T) {
	testBin := testutils.RepoRootPath("contrib/tester-progs/trigger-test-events")
	testCmd := exec.Command(testBin)
	err := testCmd.Run()
	if err != nil {
		t.Fatalf("error executing command: %v", err)
	}
}

//revive:enable

func NewTestChecker(c ec.MultiEventChecker) *TestEventChecker {
	ret := TestEventChecker{
		eventChecker:      c,
		completionChecker: NewCompletionChecker(),
	}

	return &ret
}

// update updates the state bsaed on the given event
func (tc *TestEventChecker) update(ev ec.Event) {
	switch ev := ev.(type) {
	case *tetragon.Test:
		cpu := ev.Arg0
		tc.completionChecker.Update(cpu)
	default:
	}
}

func (tc *TestEventChecker) NextEventCheck(ev ec.Event, l *slog.Logger) (bool, error) {
	if tc.completionChecker.Done() {
		l.Info("seen events on all CPUs, finalizing test")
		return true, tc.eventChecker.FinalCheck(l)
	}

	done, err := tc.eventChecker.NextEventCheck(ev, l)
	if done {
		// underlying checker done, just return its values
		return true, err
	}

	// just update the state. In the next event, we wil check
	// whether it's time to terminate or not.
	tc.update(ev)

	return false, err
}

func (tc *TestEventChecker) FinalCheck(l *slog.Logger) error {
	// this means that we run out of events before seeing all test events.
	// Just return what the underlying checker returns
	tc.completionChecker.Reset()
	return tc.eventChecker.FinalCheck(l)
}

type CompletionChecker struct {
	cpuDone  map[uint64]bool
	remCount int
}

func NewCompletionChecker() *CompletionChecker {
	ncpus := runtime.NumCPU()
	ret := CompletionChecker{
		cpuDone:  make(map[uint64]bool, ncpus),
		remCount: 0,
	}

	// NB: We assume CPU ids are consecutive. There are systems where this
	// is not the caes (e.g., cores getting offline), but we ignore them
	// for now.
	ret.remCount = ncpus
	for i := range ncpus {
		ret.cpuDone[uint64(i)] = false
	}

	return &ret
}

func (cc *CompletionChecker) Update(cpu uint64) {
	prev := cc.cpuDone[cpu]
	cc.cpuDone[cpu] = true
	if !prev && cc.remCount > 0 {
		cc.remCount--
	}
}

func (cc *CompletionChecker) Reset() {
	for i := range cc.cpuDone {
		cc.cpuDone[i] = false
	}
	cc.remCount = len(cc.cpuDone)
}

func (cc *CompletionChecker) Done() bool {
	return cc.remCount == 0
}
