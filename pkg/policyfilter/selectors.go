// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !nok8s

package policyfilter

import "sync/atomic"

var workloadSelectorPolicyCnt atomic.Uint32

func GetSelectorPolicyID() PolicyID {
	return PolicyID(workloadSelectorPolicyCnt.Add(1) + polMaxPolicies)
}
