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
	// A value that can never match must be rejected at load.
	require.Error(t, validateBinaryDigests([]string{"sha256:abc123"}), "wrong length for sha256")
	require.Error(t, validateBinaryDigests([]string{"sha256:" + strings.Repeat("z", 64)}), "not hex")
	require.NoError(t, validateBinaryDigests([]string{"sha256:" + strings.Repeat("ab", 32)}))
	require.NoError(t, validateBinaryDigests([]string{"build-id:" + strings.Repeat("ab", 10)}),
		"build IDs have no fixed length")
}

// stubContainment makes the capability probe report containment on kernels
// without openat2, so validation runs everywhere. Safe only for tests that
// never resolve a path: the stub itself confines nothing.
func stubContainment(t *testing.T) {
	t.Helper()
	orig := openat2
	openat2 = func(dirfd int, path string, how *unix.OpenHow) (int, error) {
		return unix.Openat(dirfd, path, int(how.Flags), uint32(how.Mode))
	}
	t.Cleanup(func() { openat2 = orig })
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

// The field round-trips through the CRD, and a policy whose path exists only
// inside the container still loads: nothing opens that path at load time.
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

// A podSelector says which containers to attach to, and a containerSelector
// would narrow further than the reconciler can. Both rules are enforced by CEL
// and again in the agent, for policies that skip API-server validation.
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
	require.ErrorContains(t, preValidateUprobes(spec), "podSelector")

	withContainerSelector := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  podSelector:
    matchLabels:
      app: sshd
  containerSelector:
    matchExpressions:
    - key: name
      operator: In
      values:
      - sshd
  uprobes:
  - path: "/only/exists/in/the/container"
    symbols:
    - "test_1"
    resolvePathInContainer: true
`
	_, err = tracingpolicy.FromYAML(withContainerSelector)
	require.ErrorContains(t, err, "containerSelector")

	spec = ricSpec()
	spec.ContainerSelector = &slimv1.LabelSelector{}
	require.ErrorContains(t, preValidateUprobes(spec), "containerSelector")
}

// The child sensor rebuilds the policy from one uprobe, so the policy may hold
// exactly one and nothing else.
func TestUprobeValidationResolvePathInContainerIsExclusive(t *testing.T) {
	regular := v1alpha1.UProbeSpec{Path: "/bin/app", Symbols: []string{"main"}}

	mixed := ricSpec()
	mixed.UProbes = append(mixed.UProbes, regular)
	require.ErrorContains(t, preValidateUprobes(mixed), "one resolvePathInContainer uprobe")

	two := ricSpec()
	two.UProbes = append(two.UProbes, *two.UProbes[0].DeepCopy())
	require.ErrorContains(t, preValidateUprobes(two), "one resolvePathInContainer uprobe")

	// A policy section other than uprobes is already rejected globally.
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

// The spec is validated at load even though its path is not opened, so an
// invalid policy fails immediately instead of failing every container attach.
func TestUprobeValidationResolvePathInContainerValidatesSpec(t *testing.T) {
	stubContainment(t)
	noAddressing := ricSpec()
	noAddressing.UProbes[0].Symbols = nil
	require.ErrorContains(t, preValidateUprobes(noAddressing),
		"exactly one of either Symbols, Offsets or Addrs")

	badSymbol := ricSpec()
	badSymbol.UProbes[0].Symbols = []string{"main+not-an-offset"}
	require.ErrorContains(t, preValidateUprobes(badSymbol), "wrong offset")

	badArg := ricSpec()
	badArg.UProbes[0].Args = []v1alpha1.KProbeArg{{Index: 5, Type: "int"}}
	require.ErrorContains(t, preValidateUprobes(badArg), "Index 5 out of bounds")
}

// binaryDigests is verified per container against the resolved binary, so the
// combination is allowed. A malformed digest could never match, and ignoring a
// mismatch would only turn a skip into an attach with no uprobes.
func TestUprobeValidationResolvePathInContainerDigests(t *testing.T) {
	stubContainment(t)
	ok := ricSpec()
	ok.UProbes[0].BinaryDigests = []string{"sha256:" + strings.Repeat("0", 64)}
	require.NoError(t, preValidateUprobes(ok))

	malformed := ricSpec()
	malformed.UProbes[0].BinaryDigests = []string{"not-a-valid-digest"}
	require.ErrorContains(t, preValidateUprobes(malformed), "digest")

	ignored := ricSpec()
	ignored.UProbes[0].BinaryDigests = []string{"sha256:" + strings.Repeat("0", 64)}
	ignored.UProbes[0].Ignore = &v1alpha1.UprobeIgnore{DigestVerificationFailure: true}
	require.ErrorContains(t, preValidateUprobes(ignored), "ignore.digestVerificationFailure")
}

// Without containment, a symlink planted in a container could redirect the
// attach to a host binary.
func TestUprobeValidationResolvePathInContainerNeedsContainment(t *testing.T) {
	openat2Orig := openat2
	openat2 = func(int, string, *unix.OpenHow) (int, error) {
		return -1, unix.ENOSYS
	}
	t.Cleanup(func() { openat2 = openat2Orig })

	require.ErrorIs(t, preValidateUprobes(ricSpec()), errNoContainment)
}

func TestUprobeValidationResolvePathInContainerAllowed(t *testing.T) {
	requireOpenat2InRoot(t)
	require.NoError(t, preValidateUprobes(ricSpec()))
}

func TestUprobeEventConfigCarriesPolicyID(t *testing.T) {
	var state uprobeConfigState
	err := initUprobeArgs(&v1alpha1.UProbeSpec{}, &uprobeHas{}, &addUprobeIn{policyID: 7}, &state)
	require.NoError(t, err)
	require.Equal(t, uint32(7), state.eventConfig.PolicyID)
}
