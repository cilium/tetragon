// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

func TestActCountsCheckSelectorPost(t *testing.T) {
	stats := func(posts ...uint64) *tetragon.TracingPolicyStats {
		s := &tetragon.TracingPolicyStats{}
		for i, post := range posts {
			s.SelectorActionCounters = append(s.SelectorActionCounters, &tetragon.TracingPolicySelectorActionCounters{
				HookIndex:      wrapperspb.UInt32(0),
				SelectorIndex:  wrapperspb.UInt32(uint32(i)),
				ActionCounters: &tetragon.TracingPolicyActionCounters{Post: post},
			})
		}
		return s
	}
	expect := &ActionCounts{SelectorPost: map[SelectorIndex]uint64{{Selector: 0}: 1, {Selector: 1}: 0}}

	require.NoError(t, ActCountsCheck(false, stats(2, 5), stats(3, 5), expect))
	require.ErrorContains(t, ActCountsCheck(false, stats(2, 5), stats(3, 6), expect),
		"post (hook 0, selector 1): expected:0 before:5, after:6")
}
