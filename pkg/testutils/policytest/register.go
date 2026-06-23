// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"slices"
	"strings"
)

type RegisteredPolicyTests struct {
	tests []*T
}

func (rpt *RegisteredPolicyTests) Len() int {
	return len(rpt.tests)
}

func (rpt *RegisteredPolicyTests) GetByName(name string) []*T {
	return rpt.GetByFunction(func(t *T) bool {
		return name == t.Name
	})
}

func (rpt *RegisteredPolicyTests) GetByFunction(fn func(t *T) bool) []*T {
	var ret []*T
	for _, t := range rpt.tests {
		if fn(t) {
			ret = append(ret, t)
		}
	}
	slices.SortFunc(ret, func(a, b *T) int {
		return strings.Compare(a.Name, b.Name)
	})
	return ret
}

func (rpt *RegisteredPolicyTests) Get(index int) *T {
	return rpt.tests[index]
}

var AllPolicyTests = &RegisteredPolicyTests{}

// RegisterPolicyTestAtInit registers a policytest at init, so it does not synchronize access to the
// global slice
func RegisterPolicyTestAtInit(t *T) {
	AllPolicyTests.tests = append(AllPolicyTests.tests, t)
}
