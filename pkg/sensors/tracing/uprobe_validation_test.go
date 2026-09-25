// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"
)

func TestValidateBinaryDigests(t *testing.T) {
	require.NoError(t, validateBinaryDigests([]string{"sha256:" + strings.Repeat("ab", 32), "build-id:deadbeef"}))
	for _, d := range []string{"", "md5:abc", "sha256:abc123", "sha256:" + strings.Repeat("z", 64)} {
		require.Error(t, validateBinaryDigests([]string{d}), d)
	}
}

func ricSpec() *v1alpha1.TracingPolicySpec {
	return &v1alpha1.TracingPolicySpec{
		PodSelector: &slimv1.LabelSelector{},
		UProbes: []v1alpha1.UProbeSpec{{
			Path:                   "/only/exists/in/the/container",
			Symbols:                []string{"test_1"},
			ResolvePathInContainer: true,
		}},
	}
}

func TestValidateResolvePathInContainer(t *testing.T) {
	requireOpenat2InRoot(t)
	tests := []struct {
		name    string
		modify  func(*v1alpha1.TracingPolicySpec)
		wantErr string
	}{
		{name: "valid", modify: func(*v1alpha1.TracingPolicySpec) {}},
		{name: "mixed with a regular uprobe", modify: func(s *v1alpha1.TracingPolicySpec) {
			s.UProbes = append(s.UProbes, v1alpha1.UProbeSpec{Path: "/bin/app", Symbols: []string{"main"}})
		}},
		{name: "no podSelector", wantErr: "podSelector", modify: func(s *v1alpha1.TracingPolicySpec) {
			s.PodSelector = nil
		}},
		{name: "hostSelector", wantErr: "hostSelector", modify: func(s *v1alpha1.TracingPolicySpec) {
			s.HostSelector = &slimv1.LabelSelector{}
		}},
		{name: "relative path", wantErr: "spec.uprobes[1]: resolvePathInContainer requires an absolute path",
			modify: func(s *v1alpha1.TracingPolicySpec) {
				u := *s.UProbes[0].DeepCopy()
				u.Path = "usr/bin/app"
				s.UProbes = append(s.UProbes, u)
			}},
		{name: "invalid args", wantErr: "Index 5 out of bounds", modify: func(s *v1alpha1.TracingPolicySpec) {
			s.UProbes[0].Args = []v1alpha1.KProbeArg{{Index: 5, Type: "int"}}
		}},
		{name: "ignored digest", wantErr: "ignore.digestVerificationFailure", modify: func(s *v1alpha1.TracingPolicySpec) {
			s.UProbes[0].BinaryDigests = []string{"sha256:" + strings.Repeat("0", 64)}
			s.UProbes[0].Ignore = &v1alpha1.UprobeIgnore{DigestVerificationFailure: true}
		}},
		{name: "matchUserCallers in a macro", wantErr: "matchUserCallers", modify: func(s *v1alpha1.TracingPolicySpec) {
			s.SelectorsMacros = map[string]v1alpha1.KProbeSelector{
				"callers": {MatchUserCallers: []v1alpha1.UserCallerSelector{{Depth: "1", Symbol: "main"}}},
			}
			s.UProbes[0].Selectors = []v1alpha1.KProbeSelector{{Macros: []string{"callers"}}}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := ricSpec()
			tt.modify(spec)
			err := validateResolvePathInContainer(spec)
			if tt.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tt.wantErr)
			}
		})
	}
}

func TestUprobeValidationResolvePathInContainerDefersPath(t *testing.T) {
	requireOpenat2InRoot(t)
	require.NoError(t, checkCrd(t, `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  podSelector:
    matchLabels:
      app: sshd
  uprobes:
  - path: "/only/exists/in/the/container"
    symbols:
    - "pam_authenticate"
    resolvePathInContainer: true
`))
}

func TestUprobeEventConfigCarriesPolicyID(t *testing.T) {
	var state uprobeConfigState
	err := initUprobeArgs(&v1alpha1.UProbeSpec{}, &uprobeHas{}, &addUprobeIn{policyID: 7}, &state)
	require.NoError(t, err)
	require.Equal(t, uint32(7), state.eventConfig.PolicyID)
}

// The enforcer actions are only implemented for kprobes and tracepoints, so
// they have to be rejected here rather than silently do nothing.
func TestUprobeValidationEnforcerAction(t *testing.T) {
	err := checkCrd(t, `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe-notify-enforcer"
spec:
  uprobes:
  - path: "/proc/self/exe"
    symbols: ["main"]
    selectors:
    - matchActions:
      - action: NotifyEnforcer
`)
	require.Error(t, err)
	require.Contains(t, err.Error(), "enforcer actions are not supported")
}

func TestUprobeValidationStackTraceRequiresPost(t *testing.T) {
	tests := []struct {
		name       string
		action     v1alpha1.ActionSelector
		wantErrMsg string
	}{
		{
			name: "kernel stack with Post action",
			action: v1alpha1.ActionSelector{
				Action:           "Post",
				KernelStackTrace: true,
			},
			wantErrMsg: "kernelStackTrace is not supported for uprobes",
		},
		{
			name: "user stack with non-Post action",
			action: v1alpha1.ActionSelector{
				Action:         "NoPost",
				UserStackTrace: true,
			},
			wantErrMsg: "userStackTrace can only be used along Post action",
		},
		{
			name: "user stack with Post action",
			action: v1alpha1.ActionSelector{
				Action:         "Post",
				UserStackTrace: true,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec := &v1alpha1.UProbeSpec{
				Symbols: []string{"main"},
				Selectors: []v1alpha1.KProbeSelector{{
					MatchActions: []v1alpha1.ActionSelector{test.action},
				}},
			}

			err := validateUprobeSpec(spec, &uprobeConfigState{})
			if test.wantErrMsg != "" {
				require.ErrorContains(t, err, test.wantErrMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
