// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package test

import (
	"runtime"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/sirupsen/logrus"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
)

//revive:disable

// TestChecker is a checker that relies on:
//  - the test sensor being loaded
//  - user-space executing hooks that trigger the test sensor on all cores
//  (see contrib/tester-progs/trigger-test-events).
//
// The typical structure of a test is:
//   1. start observer
//   2. do some things on user-space
//   3. check that we get the expected events from tetragon
//
// The above approach requires retries for step 3 if the events we are looking
// for are not there. These retry counts are large so that we can deal with
// worst case scenarios, and, subsequently, they induce a significant time cost
// in failing tests. Furthermore, for some tests we also need to check for the
// absence of events (e.g., when doing filtering), which also requires waiting
// on timeouts.
//
// The TestChecker enables testing without timeouts. We still use timeouts for
// robustness, but if the TestChecker works correctly, they are not needed.
// TestChecker offers a way to end the test even if we have not receive the
// expected events.
//
// The idea is simple: after step 2, we trigger the hook of the test sensor on
// all CPUs. Once we 've seen all the test events (on all CPUs), then we know
// that if we expect any events, they are not there.
type TestChecker struct {
	checker       ec.MultiEventChecker
	testDone      map[uint64]bool
	testDoneCount int
}

//revive:enable

func NewTestChecker(c ec.MultiEventChecker) *TestChecker {
	ncpus := runtime.NumCPU()
	ret := TestChecker{
		checker:  c,
		testDone: make(map[uint64]bool, ncpus),
	}

	// NB: We assume CPU ids are consecutive. There are systems where this
	// is not the caes (e.g., cores getting offline), but we ignore them
	// for now.
	ret.testDoneCount = ncpus
	for i := 0; i < ncpus; i++ {
		ret.testDone[uint64(i)] = false
	}

	return &ret
}

// update updates the state bsaed on the given event
func (tc *TestChecker) update(ev ec.Event) {
	switch ev := ev.(type) {
	case *tetragon.Test:
		cpu := ev.Arg0
		prev := tc.testDone[cpu]
		tc.testDone[cpu] = true
		if !prev && tc.testDoneCount > 0 {
			tc.testDoneCount--
		}
	default:
	}
}

// reset resets internal state
func (tc *TestChecker) reset() {
	for i := range tc.testDone {
		tc.testDone[i] = false
	}
	tc.testDoneCount = len(tc.testDone)
}

func (tc *TestChecker) seenAllTestEvents() bool {
	return tc.testDoneCount == 0
}

func (tc *TestChecker) NextEventCheck(ev ec.Event, l *logrus.Logger) (bool, error) {
	if tc.seenAllTestEvents() {
		l.Info("seen events on all CPUs, finalizing test")
		return true, tc.checker.FinalCheck(l)
	}

	done, err := tc.checker.NextEventCheck(ev, l)
	if done {
		// underlying checker done, just return its values
		return true, err
	}

	// just update the state. In the next event, we wil check
	// whether it's time to terminate or not.
	tc.update(ev)

	return false, err
}

func (tc *TestChecker) FinalCheck(l *logrus.Logger) error {
	// this means that we run out of events before seeing all test events.
	// Just return what the underlying checker returns
	tc.reset()
	return tc.checker.FinalCheck(l)
}
