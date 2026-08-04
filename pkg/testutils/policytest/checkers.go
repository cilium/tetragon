// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/tetragoninfo"
)

func processCacheDisabled(info *tetragoninfo.Info) bool {
	if info != nil {
		disabledPC, _ := info.Conf["disable-process-cache"].(bool)
		return disabledPC
	}
	return false
}

// unsetProcessChecks strips any Process check set via WithProcess() from the
// individual checkers of a scenario's EventChecker, e.g. for cases where the
// process cache is disabled and the Process field can't be checked.
func unsetProcessChecks(checker ec.MultiEventChecker) {
	getter, ok := checker.(interface{ GetChecks() []ec.EventChecker })
	if !ok {
		return
	}
	for _, c := range getter.GetChecks() {
		switch v := c.(type) {
		// no case for *ec.ProcessExecChecker, because this check is
		// always valid, regardless of whether the process cache is
		// enabled or disabled
		case *ec.ProcessExitChecker:
			v.UnsetProcess()
		case *ec.ProcessKprobeChecker:
			v.UnsetProcess()
		case *ec.ProcessTracepointChecker:
			v.UnsetProcess()
		case *ec.ProcessUprobeChecker:
			v.UnsetProcess()
		case *ec.ProcessUsdtChecker:
			v.UnsetProcess()
		case *ec.ProcessLsmChecker:
			v.UnsetProcess()
		case *ec.ProcessLoaderChecker:
			v.UnsetProcess()
		}
	}
}

// unsetParentChecks strips any Parent check set via WithParent() from the
// individual checkers of a scenario's EventChecker, e.g. for cases where the
// process cache is disabled and the Parent field can't be checked.
func unsetParentChecks(checker ec.MultiEventChecker) {
	getter, ok := checker.(interface{ GetChecks() []ec.EventChecker })
	if !ok {
		return
	}
	for _, c := range getter.GetChecks() {
		switch v := c.(type) {
		case *ec.ProcessExecChecker:
			v.UnsetParent()
		case *ec.ProcessExitChecker:
			v.UnsetParent()
		case *ec.ProcessKprobeChecker:
			v.UnsetParent()
		case *ec.ProcessTracepointChecker:
			v.UnsetParent()
		case *ec.ProcessUprobeChecker:
			v.UnsetParent()
		case *ec.ProcessUsdtChecker:
			v.UnsetParent()
		case *ec.ProcessLsmChecker:
			v.UnsetParent()
		case *ec.ProcessLoaderChecker:
			v.UnsetParent()
		}
	}
}
