// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"fmt"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

type ActionCounts struct {
	Post           *uint64
	Signal         *uint64
	Override       *uint64
	NotifyEnforcer *uint64
}

func (ac *ActionCounts) empty() bool {
	return ac.Post == nil && ac.Signal == nil && ac.Override == nil && ac.NotifyEnforcer == nil
}

func actCountsCheck(
	monitorMode bool,
	before, after *tetragon.TracingPolicyActionCounters,
	expect *ActionCounts,
) error {

	var err error
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

	return err
}
