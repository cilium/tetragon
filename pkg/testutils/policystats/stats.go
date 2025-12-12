// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policystats

import (
	"testing"

	"github.com/stretchr/testify/require"

	ps "github.com/cilium/tetragon/pkg/policystats"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

// ExpectedPolicyActions describes the expected delta for each policy action counter
// between two snapshots.
type ExpectedPolicyActions struct {
	Post, Signal, MonitorSignal,
	Override, MonitorOverride,
	NotifyEnforcer, MonitorNotifyEnforcer uint64
}

// Checker holds a check function that verifies that policy statistics
// counters changed by the expected deltas.
type Checker struct {
	Check func()
}

// NewChecker captures a snapshot of policy statistics for the given tracing
// policy and returns a Checker whose Check method asserts that the stats
// counters changed by the expected deltas.
//
// Typical usage in tests:
//
//	checker := NewChecker(<*T>, <TracingPolicy>, ExpectedPolicyActions{
//		Post:   1,
//		Signal: 1,
//	})
//	// run operations that should trigger the policy actions above
//	checker.Check()
func NewChecker(t *testing.T, tp tracingpolicy.TracingPolicy, expected ExpectedPolicyActions) Checker {
	before, err := ps.GetPolicyStats(tp)
	require.NoError(t, err)

	return Checker{
		Check: func() {
			after, err := ps.GetPolicyStats(tp)
			require.NoError(t, err)

			require.Equal(
				t,
				before.ActionsCount[ps.PolicyPost]+expected.Post,
				after.ActionsCount[ps.PolicyPost],
				"PolicyPost delta mismatch: before=%d after=%d expectedDelta=%d",
				before.ActionsCount[ps.PolicyPost],
				after.ActionsCount[ps.PolicyPost],
				expected.Post,
			)
			require.Equal(
				t,
				before.ActionsCount[ps.PolicySignal]+expected.Signal,
				after.ActionsCount[ps.PolicySignal],
				"PolicySignal delta mismatch: before=%d after=%d expectedDelta=%d",
				before.ActionsCount[ps.PolicySignal],
				after.ActionsCount[ps.PolicySignal],
				expected.Signal,
			)
			require.Equal(
				t,
				before.ActionsCount[ps.PolicyMonitorSignal]+expected.MonitorSignal,
				after.ActionsCount[ps.PolicyMonitorSignal],
				"PolicyMonitorSignal delta mismatch: before=%d after=%d expectedDelta=%d",
				before.ActionsCount[ps.PolicyMonitorSignal],
				after.ActionsCount[ps.PolicyMonitorSignal],
				expected.MonitorSignal,
			)
			require.Equal(
				t,
				before.ActionsCount[ps.PolicyOverride]+expected.Override,
				after.ActionsCount[ps.PolicyOverride],
				"PolicyOverride delta mismatch: before=%d after=%d expectedDelta=%d",
				before.ActionsCount[ps.PolicyOverride],
				after.ActionsCount[ps.PolicyOverride],
				expected.Override,
			)
			require.Equal(
				t,
				before.ActionsCount[ps.PolicyMonitorOverride]+expected.MonitorOverride,
				after.ActionsCount[ps.PolicyMonitorOverride],
				"PolicyMonitorOverride delta mismatch: before=%d after=%d expectedDelta=%d",
				before.ActionsCount[ps.PolicyMonitorOverride],
				after.ActionsCount[ps.PolicyMonitorOverride],
				expected.MonitorOverride,
			)
			require.Equal(
				t,
				before.ActionsCount[ps.PolicyNotifyEnforcer]+expected.NotifyEnforcer,
				after.ActionsCount[ps.PolicyNotifyEnforcer],
				"PolicyNotifyEnforcer delta mismatch: before=%d after=%d expectedDelta=%d",
				before.ActionsCount[ps.PolicyNotifyEnforcer],
				after.ActionsCount[ps.PolicyNotifyEnforcer],
				expected.NotifyEnforcer,
			)
			require.Equal(
				t,
				before.ActionsCount[ps.PolicyMonitorNotifyEnforcer]+expected.MonitorNotifyEnforcer,
				after.ActionsCount[ps.PolicyMonitorNotifyEnforcer],
				"PolicyMonitorNotifyEnforcer delta mismatch: before=%d after=%d expectedDelta=%d",
				before.ActionsCount[ps.PolicyMonitorNotifyEnforcer],
				after.ActionsCount[ps.PolicyMonitorNotifyEnforcer],
				expected.MonitorNotifyEnforcer,
			)
		},
	}
}
