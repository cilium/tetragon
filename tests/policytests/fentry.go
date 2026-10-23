// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tests

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/bpf"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/testutils/policytest"
)

const kptrRestrictPath = "/proc/sys/kernel/kptr_restrict"

func readKptrRestrict() (string, error) {
	value, err := os.ReadFile(kptrRestrictPath)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(value)), nil
}

func writeKptrRestrict(value string) error {
	return os.WriteFile(kptrRestrictPath, []byte(value+"\n"), 0)
}

func canSetKptrRestrict() string {
	original, err := readKptrRestrict()
	if err != nil {
		return fmt.Sprintf("cannot read %s: %v", kptrRestrictPath, err)
	}
	if err := writeKptrRestrict("2"); err != nil {
		return fmt.Sprintf("cannot change %s: %v", kptrRestrictPath, err)
	}
	if err := writeKptrRestrict(original); err != nil {
		return fmt.Sprintf("cannot restore %s after permission check: %v", kptrRestrictPath, err)
	}
	return ""
}

const fentryKptrRestrictPolicy = policytest.Policy(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "fentry-kptr-restrict"
spec:
  fentries:
  - call: "security_file_open"
    syscall: false
    args:
    - index: 0
      type: "file"
    selectors:
    - matchArgs:
      - index: 0
        operator: "Postfix"
        values:
        - "/id"
`)

var _ = func() any {
	test := &policytest.T{
		Name:   "fentry-kptr-restrict",
		Labels: []policytest.Label{"fentries"},
		ShouldSkip: func(si *policytest.SkipInfo) string {
			if si.AgentInfo == nil || !si.AgentInfo.Probes[bpf.Fentry] {
				return "fentry hook depends on fentry support"
			}
			return canSetKptrRestrict()
		},
		Policy: func(_ *policytest.Conf) (policytest.Policy, policytest.PolicyCleanupFn, error) {
			original, err := readKptrRestrict()
			if err != nil {
				return "", nil, fmt.Errorf("read %s: %w", kptrRestrictPath, err)
			}
			if err := writeKptrRestrict("2"); err != nil {
				// Real runs go through ShouldSkip first, so permission errors
				// only come from callers that just render the policy (like
				// TestRenderPolicyTests), return the policy for them.
				if !errors.Is(err, fs.ErrPermission) {
					return "", nil, fmt.Errorf("set %s to 2: %w", kptrRestrictPath, err)
				}
				return fentryKptrRestrictPolicy, func() {}, nil
			}

			cleanup := func() {
				if err := writeKptrRestrict(original); err != nil {
					panic(fmt.Errorf("restore %s to %s: %w", kptrRestrictPath, original, err))
				}
			}
			return fentryKptrRestrictPolicy, cleanup, nil
		},
		Scenarios: []func(*policytest.Conf) *policytest.Scenario{
			func(_ *policytest.Conf) *policytest.Scenario {
				checker := ec.NewProcessKprobeChecker("fentry-kptr-restrict").
					WithFunctionName(sm.Full("security_file_open")).
					WithArgs(ec.NewKprobeArgumentListMatcher().
						WithValues(ec.NewKprobeArgumentChecker().WithFileArg(
							ec.NewKprobeFileChecker().WithPath(sm.Suffix("/id")),
						)))
				return &policytest.Scenario{
					Name:         "open /usr/bin/id and check fentry event",
					Trigger:      policytest.NewCmdTrigger("/usr/bin/id"),
					EventChecker: ec.NewUnorderedEventChecker(checker),
				}
			},
		},
	}
	policytest.RegisterPolicyTestAtInit(test)
	return nil
}()
