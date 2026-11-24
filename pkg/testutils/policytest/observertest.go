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

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/jsonchecker"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/testutils"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/cilium/tetragon/pkg/tetragoninfo"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

var getAgentInfo = sync.OnceValue(func() *tetragoninfo.Info {
	res := tetragoninfo.Gather()
	return tetragoninfo.Decode(res)
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
		skipInfo := SkipInfo{getAgentInfo(), ParamVals(params)}
		if skipReason := pt.ShouldSkip(&skipInfo); skipReason != "" {
			t.Skip(skipReason)
		}
	}

	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	conf := &Conf{
		BinsDir: testutils.RepoRootPath("contrib/tester-progs"),
		TestConf: &TestConf{
			ParamValues: params,
		},
	}
	policyStr, cleanupFn, err := pt.Policy(conf)
	if err != nil {
		t.Fatalf("failed to generate policy: %s", err)
	}
	t.Cleanup(cleanupFn)

	policyFile, err := os.CreateTemp("", "tetragon-policy-"+t.Name()+"-*.txt")
	if err != nil {
		t.Fatalf("failed to create polcy file: %s", err)
	}
	tp, err := tracingpolicy.FromYAML(string(policyStr))
	if err != nil {
		t.Fatalf("failed to parse policy: %s", err)
	}
	policyFile.WriteString(string(policyStr))
	policyFile.Close()
	policyFname := policyFile.Name()

	obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, policyFname, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}

	// Read events once for all scenarios: concurrent readers of the same
	// event buffer would race for events, losing or duplicating them.
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	for _, s := range pt.Scenarios {
		scenario := s(conf)
		var statsBefore *tetragon.TracingPolicyStats
		if !scenario.ActCountChecker.empty() {
			statsBefore = observerPolicyStats(ctx, t, tp.TpName())
		}
		err = scenario.Trigger.Trigger(ctx)
		if err != nil {
			t.Fatalf("failed to trigger scenario %s: %v", scenario.Name, err)
		}
		if statsBefore != nil {
			statsAfter := observerPolicyStats(ctx, t, tp.TpName())
			err = actCountsCheck(false, statsBefore.GetActionCounters(), statsAfter.GetActionCounters(),
				&scenario.ActCountChecker)
			require.NoError(t, err, "scenario %s: action counts", scenario.Name)
		}

		err = jsonchecker.JsonTestCheckExpect(t, scenario.EventChecker, scenario.ExpectCheckerFailure)
		require.NoError(t, err)
	}
}

func observerPolicyStats(ctx context.Context, t *testing.T, name string) *tetragon.TracingPolicyStats {
	t.Helper()
	res, err := observer.GetSensorManager().ListTracingPolicies(ctx, "")
	require.NoError(t, err)
	for _, pol := range res.GetPolicies() {
		if pol.Name == name {
			return pol.GetStats()
		}
	}
	t.Fatalf("policy %q not found", name)
	return nil
}
