// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package kube

import "github.com/cilium/tetragon/pkg/testutils/policytest"

// resultError is a typed error reconstructed from a serialized error string.
// It is a distinct type (rather than errors.New) so it does not trip the
// err113 linter, which forbids dynamic errors.
type resultError string

func (e resultError) Error() string { return string(e) }

func errOrNil(s string) error {
	if s == "" {
		return nil
	}
	return resultError(s)
}

// ToResults converts decoded results back into policytest.Result values (with
// errors reconstructed from their serialized strings) so they can be rendered
// with policytest.DumpResults. It returns the test names alongside the results,
// in the order expected by DumpResults.
func ToResults(results []TestResult) ([]string, []*policytest.Result) {
	names := make([]string, 0, len(results))
	out := make([]*policytest.Result, 0, len(results))
	for _, tr := range results {
		r := &policytest.Result{
			Skipped: tr.Skipped,
			Err:     errOrNil(tr.Err),
		}
		for _, s := range tr.Scenarios {
			r.ScenariosRes = append(r.ScenariosRes, policytest.ScenarioRes{
				Name:            s.Name,
				TriggerErr:      errOrNil(s.TriggerErr),
				CheckerErr:      errOrNil(s.CheckerErr),
				ActionCountsErr: errOrNil(s.ActionCountsErr),
			})
		}
		names = append(names, tr.Name)
		out = append(out, r)
	}
	return names, out
}
