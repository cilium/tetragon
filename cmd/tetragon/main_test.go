// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"context"
	"os"
	"testing"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/testutils"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	ec := tus.TestSensorsRun(m, "Exec")
	os.Exit(ec)
}

// The test starts tetragon with minimal setup and stops it
// when it observer is ready. By that time we should have
// exec events generated, make sure it's done.
func TestGeneratedExecEvents(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ready := func() {
		cancel()
	}

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

	err = tetragonExecuteCtx(ctx, cancel, ready)
	assert.NoError(t, err)

	// Make sure exec event with pid 1 was generated
	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("").WithProcess(
			ec.NewProcessChecker().WithPid(1)),
	)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}
