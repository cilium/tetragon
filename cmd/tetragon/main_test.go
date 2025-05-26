// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package main

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/constants"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/testutils"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	ec := tus.TestSensorsRun(m, "Exec")
	os.Exit(ec)
}

// The test starts tetragon with minimal setup and stops it
// when it observer is ready. By that time we should have
// exec events generated, make sure it's done.
// ToDo: Enable on Windows once windows programs start compiling
// and are present in the obj directory
func TestGeneratedExecEvents(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	// Minimal config to start tetragon
	option.Config.ExportRateLimit = -1
	option.Config.DataCacheSize = 1024
	option.Config.ProcessCacheSize = 65536
	option.Config.BpfDir = defaults.DefaultMapPrefix
	option.Config.HubbleLib = tus.Conf().TetragonLib
	option.Config.TracingPolicyDir = defaults.DefaultTpDir

	// Configure export file
	f, err := testutils.CreateExportFile(t)
	if err != nil {
		t.Fatalf("testutils.CreateExportFilefailed: %v\n", err)
	}
	defer f.Close()

	fname, err := testutils.GetExportFilename(t)
	if err != nil {
		t.Fatalf("testutils.GetExportFilename failed: %v\n", err)
	}
	option.Config.ExportFilename = fname

	var wg sync.WaitGroup
	wg.Add(1)
	ready := func() {
		wg.Done()
	}

	errCh := make(chan error, 1)
	// Start tetragon in separate process so we can keep the whole
	// export/server machinery running until we get expected results.
	go func() {
		err = tetragonExecuteCtx(ctx, cancel, ready)
		errCh <- err
	}()

	// Wait till tetragon's observer is up and running
	wg.Wait()

	// Make sure exec event with pid 1 was generated
	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("").WithProcess(
			ec.NewProcessChecker().WithPid(constants.INIT_PROC_ID)),
	)

	// Try it 5 times and make sure exporter is up and processed all data
	// in case it lags for some reason like slow CI server.
	cnt := 0
	for cnt < 5 {
		if err = jsonchecker.JsonTestCheck(t, checker); err == nil {
			break
		}
		time.Sleep(time.Second)
		cnt++
	}

	cancel()
	require.NoError(t, err)
	// blocking on terminating tetragon
	err = <-errCh
	require.NoError(t, err)
}
