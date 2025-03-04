// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package test

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/testutils"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/sirupsen/logrus"
)

// TestTestChecker tests the test checker
func TestTestChecker(t *testing.T) {
	if _, err := os.Stat("/sys/kernel/debug/tracing/events/syscalls"); os.IsNotExist(err) {
		t.Skip("cannot use syscall tracepoints (consider enabling CONFIG_FTRACE_SYSCALLS)")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	dummyErr := errors.New("dummy error")
	dummyChecker := ec.FnEventChecker{
		NextCheckFn: func(_ ec.Event, _ *logrus.Logger) (bool, error) {
			return false, nil
		},
		FinalCheckFn: func(_ *logrus.Logger) error {
			return dummyErr
		},
	}
	errorChecker := NewTestChecker(&dummyChecker)

	obs, err := observertesthelper.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserver error: %s", err)
	}
	sensor := GetTestSensor()
	tus.LoadSensor(t, sensor)

	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	TestCheckerMarkEnd(t)

	err = jsonchecker.JsonTestCheck(t, errorChecker)
	t.Logf("got error: %v", err)
	if !errors.Is(err, dummyErr) {
		t.Fatalf("unexpected error: %v", err)
	}
	// NB: we expect the dummyErr, now that we got it mark the file to be deleted
	testutils.DoneWithExportFile(t)
}
