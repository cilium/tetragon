// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"fmt"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

// SelectorIndex identifies a selector of a policy.
type SelectorIndex struct {
	Hook     uint32
	Selector uint32
}

type ActionCounts struct {
	Post           *uint64
	Signal         *uint64
	Override       *uint64
	NotifyEnforcer *uint64
	Set            *uint64
	// SelectorPost holds the expected posts of individual selectors.
	SelectorPost map[SelectorIndex]uint64
}

// Empty returns true if no action counts are expected.
func (ac *ActionCounts) Empty() bool {
	return ac.Post == nil && ac.Signal == nil && ac.Override == nil && ac.NotifyEnforcer == nil && ac.Set == nil &&
		len(ac.SelectorPost) == 0
}

func selectorPosts(stats *tetragon.TracingPolicyStats) map[SelectorIndex]uint64 {
	posts := make(map[SelectorIndex]uint64)
	for _, c := range stats.GetSelectorActionCounters() {
		idx := SelectorIndex{
			Hook:     c.GetHookIndex().GetValue(),
			Selector: c.GetSelectorIndex().GetValue(),
		}
		posts[idx] = c.GetActionCounters().GetPost()
	}
	return posts
}

// ActCountsCheck checks that the action counts changed from before to after
// as expected. In monitor mode, the monitor counters of enforcement actions
// are checked instead, and no signals are expected.
func ActCountsCheck(
	monitorMode bool,
	beforeStats, afterStats *tetragon.TracingPolicyStats,
	expect *ActionCounts,
) error {
	var err error
	before, after := beforeStats.GetActionCounters(), afterStats.GetActionCounters()
	doCheck := func(cnt string, expected, before, after uint64) {
		if expected != after-before {
			err = addErr(err, cnt, fmt.Errorf("expected:%d before:%d, after:%d", expected, before, after))
		}
	}

	if expect.Post != nil {
		doCheck("post", *(expect.Post), before.Post, after.Post)
	}

	if expect.Signal != nil {
		if monitorMode {
			doCheck("signal", 0, before.Signal, after.Signal)
		} else {
			doCheck("signal", *(expect.Signal), before.Signal, after.Signal)
		}
	}

	if expect.Override != nil {
		if monitorMode {
			doCheck("override (monitor)", *(expect.Override), before.MonitorOverride, after.MonitorOverride)
		} else {
			doCheck("override", *(expect.Override), before.Override, after.Override)
		}
	}

	if expect.NotifyEnforcer != nil {
		if monitorMode {
			doCheck("notify-enforcer (monitor)", *(expect.NotifyEnforcer), before.MonitorNotifyEnforcer, after.MonitorNotifyEnforcer)
		} else {
			doCheck("notify-enforcer", *(expect.NotifyEnforcer), before.NotifyEnforcer, after.NotifyEnforcer)
		}
	}

	if expect.Set != nil {
		if monitorMode {
			doCheck("set (monitor)", *(expect.Set), before.MonitorSet, after.MonitorSet)
		} else {
			doCheck("set", *(expect.Set), before.Set, after.Set)
		}
	}

	if len(expect.SelectorPost) > 0 {
		postsBefore, postsAfter := selectorPosts(beforeStats), selectorPosts(afterStats)
		for idx, expected := range expect.SelectorPost {
			name := fmt.Sprintf("post (hook %d, selector %d)", idx.Hook, idx.Selector)
			doCheck(name, expected, postsBefore[idx], postsAfter[idx])
		}
	}

	return err
}
