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
	"github.com/cilium/tetragon/pkg/tetragoninfo"
)

var getSkipInfo = sync.OnceValue(func() *SkipInfo {
	res := tetragoninfo.Gather()
	info := tetragoninfo.Decode(res)
	return &SkipInfo{info}
})

func (rpt *RegisteredPolicyTests) DoObserverTest(
	t *testing.T,
	testpolicyName string,
	params map[string]any,
) {
	t.Helper()
	pts := rpt.GetByName(testpolicyName)
	if len(pts) == 0 {
		t.Fatalf("no testpolicy with name %q found", testpolicyName)
	} else if len(pts) > 1 {
		t.Fatalf(">1 testpolicies with name %q found", testpolicyName)
	}
	pt := pts[0]

	if pt.ShouldSkip != nil {
		if skipReason := pt.ShouldSkip(getSkipInfo()); skipReason != "" {
			t.Skip(skipReason)
		}
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	if pt.Setup != nil {
		if cleanup := pt.Setup(); cleanup != nil {
			defer cleanup()
		}
	}

	conf := &Conf{
		BinsDir: testutils.RepoRootPath("contrib/tester-progs"),
		TestConf: &TestConf{
			ParamValues: params,
		},
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

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, policyFname, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}

	for _, s := range pt.Scenarios {
		observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
		readyWG.Wait()

		scenario := s(conf)
		err = scenario.Trigger.Trigger(ctx)
		if err != nil {
			t.Fatalf("failed to trigger scenario %s", scenario.Name)
		}

		err = jsonchecker.JsonTestCheckExpect(t, scenario.EventChecker, scenario.ExpectCheckerFailure)
		require.NoError(t, err)
	}
}
