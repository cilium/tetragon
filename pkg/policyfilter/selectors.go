// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !nok8s

package policyfilter

import "sync/atomic"

var ops atomic.Uint32

func GetSelectorPolicyID() PolicyID {
	return PolicyID(ops.Add(1) + polMaxPolicies)
}
