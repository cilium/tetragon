// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/tetragon/pkg/testutils"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

func TestValidateBinaryDigests(t *testing.T) {
	require.NoError(t, validateBinaryDigests(nil))
	require.NoError(t, validateBinaryDigests([]string{"build-id:deadbeef"}),
		"build-id is a valid identifier algorithm")
	require.Error(t, validateBinaryDigests([]string{""}), "empty entry must be rejected")
	require.Error(t, validateBinaryDigests([]string{"not-a-digest"}), "missing <algo>: separator")
	require.Error(t, validateBinaryDigests([]string{"md5:abc"}), "unsupported algorithm")
	require.Error(t, validateBinaryDigests([]string{"sha256:"}), "empty value")
	require.Error(t, validateBinaryDigests([]string{"sha256:abc123"}), "wrong length for sha256")
	require.Error(t, validateBinaryDigests([]string{"sha256:" + strings.Repeat("z", 64)}), "not hex")
	require.NoError(t, validateBinaryDigests([]string{"sha256:" + strings.Repeat("ab", 32)}))
	require.NoError(t, validateBinaryDigests([]string{"build-id:" + strings.Repeat("ab", 10)}),
		"build IDs have no fixed length")
}

func stubContainment(t *testing.T) {
	t.Helper()
	orig := openat2
	openat2 = func(dirfd int, path string, how *unix.OpenHow) (int, error) {
		return unix.Openat(dirfd, path, int(how.Flags), uint32(how.Mode))
	}
	t.Cleanup(func() { openat2 = orig })
}

func validateRIC(spec *v1alpha1.TracingPolicySpec) error {
	return validateResolvePathInContainer(spec, resolvePathInContainerSpec(spec))
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

func TestUprobeValidationResolvePathInContainer(t *testing.T) {
	stubContainment(t)
	crd := `
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
`
	tp, err := tracingpolicy.FromYAML(crd)
	require.NoError(t, err)
	require.True(t, tp.TpSpec().UProbes[0].ResolvePathInContainer)
	require.NoError(t, checkCrd(t, crd),
		"policy load must defer resolving an in-container path")

	withoutField := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  uprobes:
  - path: "/bin/bash"
    symbols:
    - "main"
`
	tp, err = tracingpolicy.FromYAML(withoutField)
	require.NoError(t, err)
	require.False(t, tp.TpSpec().UProbes[0].ResolvePathInContainer,
		"resolvePathInContainer should default to false when omitted")
}

func TestUprobeValidationResolvePathInContainerSelectors(t *testing.T) {
	noSelector := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  uprobes:
  - path: "/only/exists/in/the/container"
    symbols:
    - "test_1"
    resolvePathInContainer: true
`
	_, err := tracingpolicy.FromYAML(noSelector)
	require.ErrorContains(t, err, "podSelector")

	spec := ricSpec()
	spec.PodSelector = nil
	require.ErrorContains(t, validateRIC(spec), "podSelector")

	withHostSelector := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  podSelector:
    matchLabels:
      app: sshd
  hostSelector: {}
  uprobes:
  - path: "/only/exists/in/the/container"
    symbols:
    - "test_1"
    resolvePathInContainer: true
`
	_, err = tracingpolicy.FromYAML(withHostSelector)
	require.ErrorContains(t, err, "hostSelector")

	spec = ricSpec()
	spec.HostSelector = &slimv1.LabelSelector{}
	require.ErrorContains(t, validateRIC(spec), "hostSelector")

	spec = ricSpec()
	spec.UProbes[0].Path = "usr/bin/app"
	require.ErrorContains(t, validateRIC(spec), "absolute path")
}

func TestUprobeValidationResolvePathInContainerIsExclusive(t *testing.T) {
	regular := v1alpha1.UProbeSpec{Path: "/bin/app", Symbols: []string{"main"}}

	mixed := ricSpec()
	mixed.UProbes = append(mixed.UProbes, regular)
	require.ErrorContains(t, validateRIC(mixed), "one resolvePathInContainer uprobe")

	two := ricSpec()
	two.UProbes = append(two.UProbes, *two.UProbes[0].DeepCopy())
	require.ErrorContains(t, validateRIC(two), "one resolvePathInContainer uprobe")

	uprobe := testutils.RepoRootPath("contrib/tester-progs/regs-override")
	err := checkCrd(t, `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  podSelector:
    matchLabels:
      app: sshd
  uprobes:
  - path: "`+uprobe+`"
    symbols:
    - "test_1"
    resolvePathInContainer: true
  usdts:
  - path: "`+uprobe+`"
    provider: "test"
    name: "probe"
`)
	require.ErrorContains(t, err, "multiple sections")
}

func TestUprobeValidationResolvePathInContainerValidatesSpec(t *testing.T) {
	stubContainment(t)
	noAddressing := ricSpec()
	noAddressing.UProbes[0].Symbols = nil
	require.ErrorContains(t, validateRIC(noAddressing),
		"exactly one of either Symbols, Offsets or Addrs")

	badSymbol := ricSpec()
	badSymbol.UProbes[0].Symbols = []string{"main+not-an-offset"}
	require.ErrorContains(t, validateRIC(badSymbol), "wrong offset")

	badArg := ricSpec()
	badArg.UProbes[0].Args = []v1alpha1.KProbeArg{{Index: 5, Type: "int"}}
	require.ErrorContains(t, validateRIC(badArg), "Index 5 out of bounds")
}

func TestUprobeValidationResolvePathInContainerDigests(t *testing.T) {
	stubContainment(t)
	ok := ricSpec()
	ok.UProbes[0].BinaryDigests = []string{"sha256:" + strings.Repeat("0", 64)}
	require.NoError(t, validateRIC(ok))

	malformed := ricSpec()
	malformed.UProbes[0].BinaryDigests = []string{"not-a-valid-digest"}
	require.ErrorContains(t, validateRIC(malformed), "digest")

	ignored := ricSpec()
	ignored.UProbes[0].BinaryDigests = []string{"sha256:" + strings.Repeat("0", 64)}
	ignored.UProbes[0].Ignore = &v1alpha1.UprobeIgnore{DigestVerificationFailure: true}
	require.ErrorContains(t, validateRIC(ignored), "ignore.digestVerificationFailure")
}

func TestUprobeValidationResolvePathInContainerNeedsContainment(t *testing.T) {
	stubNoContainment(t)
	require.ErrorIs(t, validateRIC(ricSpec()), errNoContainment)
}

func TestUprobeValidationResolvePathInContainerAllowed(t *testing.T) {
	requireOpenat2InRoot(t)
	require.NoError(t, validateRIC(ricSpec()))

	narrowed := ricSpec()
	narrowed.ContainerSelector = &slimv1.LabelSelector{MatchLabels: map[string]string{"name": "sshd"}}
	require.NoError(t, validateRIC(narrowed))
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
