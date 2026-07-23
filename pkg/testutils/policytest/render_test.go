// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/testutils"
	"github.com/cilium/tetragon/pkg/testutils/policytest"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	_ "github.com/cilium/tetragon/tests/policytests" // so that the policies are registered
)

// TestRenderPolicyTests renders the policy of every registered policytest, for
// every combination of its parameters, and checks that it parses and validates.
func TestRenderPolicyTests(t *testing.T) {
	all := policytest.AllPolicyTests
	require.NotZero(t, all.Len(), "no policy tests registered")

	for i := range all.Len() {
		pt := all.Get(i)
		t.Run(pt.Name, func(t *testing.T) {
			if pt.Policy == nil {
				t.Skip("test has no policy")
			}
			for params := range pt.AllParamValues() {
				check := func(t *testing.T) {
					conf := &policytest.Conf{
						BinsDir:  testutils.RepoRootPath("contrib/tester-progs"),
						TestConf: &policytest.TestConf{ParamValues: params},
					}

					pol, cleanup, err := pt.Policy(conf)
					if cleanup != nil {
						defer cleanup()
					}
					require.NoError(t, err, "failed to generate policy")

					if len(pol) == 0 {
						t.Skip("test generated no policy")
					}

					_, err = tracingpolicy.FromYAML(string(pol))
					require.NoError(t, err, "failed to parse policy:\n%s", pol)
				}

				// Only nest a subtest when there is a parameter to name it after:
				//
				//	uprobe-generic (no params) -> uprobe-generic
				//	kprobe-lseek   (Hook)      -> kprobe-lseek/Hook=kprobes
				//	                              kprobe-lseek/Hook=fentries
				if len(pt.Params) == 0 {
					check(t)
					continue
				}
				t.Run(params.String(), check)
			}
		})
	}
}
