// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/testutils"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
)

func (rpt *RegisteredPolicyTests) DoObserverTest(t *testing.T, testpolicyName string) {
	t.Helper()
	pts := rpt.GetByName(testpolicyName)
	if len(pts) == 0 {
		t.Fatalf("no testpolicy with name %q found", testpolicyName)
	} else if len(pts) > 1 {
		t.Fatalf(">1 testpolicies with name %q found", testpolicyName)
	}
	pt := pts[0]

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	conf := &Conf{
		BinsDir: testutils.RepoRootPath("contrib/tester-progs"),
	}
	policyStr, err := pt.Policy(conf)
	if err != nil {
		t.Fatalf("failed to generate policy: %s", err)
	}

	policyFile, err := os.CreateTemp("", "teragon-policy-"+t.Name()+"-*.txt")
	if err != nil {
		t.Fatalf("failed to create polcy file: %s", err)
	}
	policyFile.WriteString(string(policyStr))
	policyFile.Close()
	policyFname := policyFile.Name()

	// NB: The reason for failing here is because we currently do not have a test with multiple
	// scenarios and I would like to test things before adding this functionality.
	if len(pt.Scenarios) != 1 {
		t.Fatalf("TODO: support >1 scenarios")
	}
	scenario := pt.Scenarios[0](conf)

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, policyFname, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	err = scenario.Trigger.Trigger(ctx)
	if err != nil {
		t.Fatalf("failed to trigger scenario %s", scenario.Name)
	}

	err = jsonchecker.JsonTestCheck(t, scenario.EventChecker)
	require.NoError(t, err)
}
