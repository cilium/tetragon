// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"context"
	"os"
	"os/exec"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	elfpkg "github.com/cilium/tetragon/pkg/elf"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/matchers/bytesmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/testutils"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
)

func TestLoader(t *testing.T) {
	if !hasLoaderEvents() {
		t.Skip("no support for loader events")
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	loaderHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "loader"
spec:
  loader: true
`

	createCrdFile(t, loaderHook)

	testNop := testutils.RepoRootPath("contrib/tester-progs/nop")

	file, err := os.Open(testNop)
	if err != nil {
		t.Fatalf("Failed to open test binary: %v\n", err)
	}

	safeELF, err := elfpkg.NewSafeELFFile(file)
	if err != nil {
		t.Fatalf("Failed to parse ELF: %v\n", err)
	}

	id, err := safeELF.ParseBuildID()
	file.Close()
	if err != nil {
		t.Fatalf("Failed to ParseBuildID: %v\n", err)
	}

	loaderChecker := ec.NewProcessLoaderChecker("").
		WithBuildid(bytesmatcher.Full(id)).
		WithPath(sm.Full(testNop))

	checker := ec.NewUnorderedEventChecker(loaderChecker)

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	if err := exec.Command(testNop).Run(); err != nil {
		t.Fatalf("Failed to execute test binary: %s\n", err)
	}
	require.NoError(t, err)

	err = jsonchecker.JsonTestCheck(t, checker)
	require.NoError(t, err)
}
