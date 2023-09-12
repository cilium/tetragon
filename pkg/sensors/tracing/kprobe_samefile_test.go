// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"context"
	"os"
	"os/exec"
	"sync"
	"testing"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	lc "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/testutils"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/stretchr/testify/assert"

	_ "github.com/cilium/tetragon/pkg/sensors/exec"
)

func TestKprobeSameFile(t *testing.T) {

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	testBin := testutils.RepoRootPath("contrib/tester-progs/samefile-tester")
	testFile, err := os.CreateTemp("", "tetragon.gotest.samefile.*.txt")
	if err != nil {
		t.Fatal(err)
	}
	testFilePath := testFile.Name()
	testCmd := exec.CommandContext(ctx, testBin, testFilePath)

	testPipes, err := testutils.NewCmdBufferedPipes(testCmd)
	if err != nil {
		t.Fatal(err)
	}
	defer testPipes.Close()

	// makeSpecFile creates a new spec file bsed on the template, and the provided arguments
	makeSpecFile := func(path string) string {
		data := map[string]string{
			"SameFileOp":  "SameFile",
			"MatchValues": path,
		}
		specName, err := testutils.GetSpecFromTemplate("samefile.yaml.tmpl", data)
		if err != nil {
			t.Fatal(err)
		}
		return specName
	}

	specFname := makeSpecFile(testFilePath)
	t.Logf("path is %s and spec file is %s", testFilePath, specFname)

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, specFname, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	if err := testCmd.Start(); err != nil {
		t.Fatalf("Failed to start command: %v", err)
	}

	logWG := testPipes.ParseAndLogCmdOutput(t, nil, nil)
	logWG.Wait()

	if err := testCmd.Wait(); err != nil {
		t.Fatalf("command failed with %s. Context error: %s", err, ctx.Err())
	}

	kprobeChecker := ec.NewProcessKprobeChecker("").
		WithFunctionName(sm.Full("security_file_permission")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().
					WithFileArg(ec.NewKprobeFileChecker().
						WithPath(sm.Full(testFilePath)).
						WithFlags(sm.Full("")),
					),
				ec.NewKprobeArgumentChecker().WithIntArg(2),
			))

	checker := ec.NewUnorderedEventChecker(
		kprobeChecker,
	)
	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}
