// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/btf"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/tetragon/pkg/testutils"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

func TestValidateBinaryDigests(t *testing.T) {
	require.NoError(t, validateBinaryDigests(nil))
	require.NoError(t, validateBinaryDigests([]string{"sha256:abc123"}))
	require.NoError(t, validateBinaryDigests([]string{"build-id:deadbeef"}),
		"build-id is a valid identifier algorithm")
	require.Error(t, validateBinaryDigests([]string{""}), "empty entry must be rejected")
	require.Error(t, validateBinaryDigests([]string{"not-a-digest"}), "missing <algo>: separator")
	require.Error(t, validateBinaryDigests([]string{"md5:abc"}), "unsupported algorithm")
	require.Error(t, validateBinaryDigests([]string{"sha256:"}), "empty value")
}

// checkDigestTarget must reject a non-regular file (a container can point the
// path at a device or FIFO that would read forever) and accept a regular file.
func TestCheckDigestTargetRejectsNonRegular(t *testing.T) {
	dir := t.TempDir()
	d, err := os.Open(dir)
	require.NoError(t, err)
	t.Cleanup(func() { d.Close() })
	require.Error(t, checkDigestTarget(d), "a directory is not a regular file")

	f, err := os.CreateTemp(dir, "bin")
	require.NoError(t, err)
	t.Cleanup(func() { f.Close() })
	require.NoError(t, checkDigestTarget(f), "a regular file is accepted")
}

// A malformed digest on a RIC uprobe must be rejected at validation, not loaded
// Enabled and then silently failing every per-container attach.
func TestUprobeValidationResolvePathInContainerRejectsMalformedDigest(t *testing.T) {
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
  - path: "/usr/bin/app"
    symbols:
    - "main"
    resolvePathInContainer: true
    binaryDigests:
    - "not-a-valid-digest"
`
	err := checkCrd(t, crd)
	require.Error(t, err)
	require.ErrorContains(t, err, "digest")
}

func TestUprobeResolvePathInContainerField(t *testing.T) {
	withField := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  podSelector:
    matchLabels:
      app: sshd
  uprobes:
  - path: "/usr/lib64/libpam.so.0.85.1"
    symbols:
    - "pam_authenticate"
    resolvePathInContainer: true
`
	tp, err := tracingpolicy.FromYAML(withField)
	require.NoError(t, err)
	require.Len(t, tp.TpSpec().UProbes, 1)
	require.True(t, tp.TpSpec().UProbes[0].ResolvePathInContainer,
		"resolvePathInContainer: true should round-trip through CRD parsing")

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
	require.Len(t, tp.TpSpec().UProbes, 1)
	require.False(t, tp.TpSpec().UProbes[0].ResolvePathInContainer,
		"resolvePathInContainer should default to false when omitted")
}

func TestUprobeValidationResolvePathInContainerRequiresPodSelector(t *testing.T) {
	uprobe := testutils.RepoRootPath("contrib/tester-progs/regs-override")

	// resolvePathInContainer without a podSelector must be rejected. The CRD (CEL)
	// catches this at parse time, so assert on FromYAML directly.
	noSelector := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  uprobes:
  - path: "` + uprobe + `"
    symbols:
    - "test_1"
    resolvePathInContainer: true
`
	_, err := tracingpolicy.FromYAML(noSelector)
	require.Error(t, err)
	require.ErrorContains(t, err, "podSelector")

	// With a podSelector the policy must validate: RIC uprobes are resolved
	// per-container at attach time, so sensor creation opens no ELF here.
	withSelector := `
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
    - "test_1"
    resolvePathInContainer: true
`
	require.NoError(t, checkCrd(t, withSelector),
		"policy load must defer resolving an in-container ELF path")
}

func TestUprobeValidationResolvePathInContainerRequiresAddressingMethod(t *testing.T) {
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
    resolvePathInContainer: true
`

	err := checkCrd(t, crd)
	require.Error(t, err)
	require.ErrorContains(t, err, "exactly one of either Symbols, Offsets or Addrs")
}

func TestUprobeValidationResolvePathInContainerRejectsInvalidArgument(t *testing.T) {
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
    - "main"
    args:
    - index: 5
      type: "int"
    resolvePathInContainer: true
`

	err := checkCrd(t, crd)
	require.Error(t, err)
	require.ErrorContains(t, err, "Index 5 out of bounds")
}

func TestUprobeValidationResolvePathInContainerRejectsInvalidSelector(t *testing.T) {
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
    - "main"
    selectors:
    - matchActions:
      - action: Post
      - action: Post
      - action: Post
      - action: Post
    resolvePathInContainer: true
`

	err := checkCrd(t, crd)
	require.Error(t, err)
	require.ErrorContains(t, err, "only 3 actions")
}

func TestUprobeValidationResolvePathInContainerChecksRequiredFeatures(t *testing.T) {
	previousBTF := btf.GetCachedBTFFile()
	require.NoError(t, btf.InitCachedBTF("", testutils.RepoRootPath("go.mod")))
	t.Cleanup(func() {
		require.NoError(t, btf.InitCachedBTF("", previousBTF))
	})

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
    - "main"
    args:
    - index: 0
      type: "char_buf"
    selectors:
    - matchArgs:
      - index: 0
        operator: SubString
        values:
        - "needle"
    resolvePathInContainer: true
`

	err := checkCrd(t, crd)
	require.Error(t, err)
	require.ErrorContains(t, err, "can't use SubString operator")
}

func TestUprobeValidationResolvePathInContainerRejectsInvalidSymbol(t *testing.T) {
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
    - "main+not-an-offset"
    resolvePathInContainer: true
`

	err := checkCrd(t, crd)
	require.Error(t, err)
	require.ErrorContains(t, err, "wrong offset")
}

func TestUprobeValidationResolvePathInContainerRejectsInvalidMetadata(t *testing.T) {
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
    - "main"
    message: "x"
    resolvePathInContainer: true
`

	err := checkCrd(t, crd)
	require.Error(t, err)
	require.ErrorContains(t, err, "message field is too short")
}

func TestUprobeValidationResolvePathInContainerRejectsInvalidTargets(t *testing.T) {
	tests := []struct {
		name string
		spec v1alpha1.UProbeSpec
		want string
	}{
		{
			name: "empty path",
			spec: v1alpha1.UProbeSpec{Symbols: []string{"main"}},
			want: "path must not be empty",
		},
		{
			name: "empty symbol",
			spec: v1alpha1.UProbeSpec{Path: "/bin/app", Symbols: []string{""}},
			want: "symbol must not be empty",
		},
		{
			name: "address ref counter dimension",
			spec: v1alpha1.UProbeSpec{
				Path:          "/bin/app",
				Addrs:         []uint64{1, 2},
				RefCtrOffsets: []uint64{1},
			},
			want: "different dimension than Addrs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.spec.ResolvePathInContainer = true
			spec := v1alpha1.TracingPolicySpec{
				PodSelector: &slimv1.LabelSelector{},
				UProbes:     []v1alpha1.UProbeSpec{tt.spec},
			}
			err := preValidateUprobes(&spec)
			require.ErrorContains(t, err, tt.want)
		})
	}
}

func TestUprobeValidationMultipleResolvePathInContainerAllowed(t *testing.T) {
	uprobe := testutils.RepoRootPath("contrib/tester-progs/regs-override")
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
  - path: "` + uprobe + `"
    symbols:
    - "test_1"
    resolvePathInContainer: true
  - path: "` + uprobe + `"
    symbols:
    - "test_2"
    resolvePathInContainer: true
`
	require.NoError(t, checkCrd(t, crd),
		"multiple resolvePathInContainer uprobes must be accepted")
}

func TestUprobeValidationMixedResolvePathInContainerRejected(t *testing.T) {
	uprobe := testutils.RepoRootPath("contrib/tester-progs/regs-override")
	mixed := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  podSelector:
    matchLabels:
      app: sshd
  uprobes:
  - path: "` + uprobe + `"
    symbols:
    - "test_1"
    resolvePathInContainer: true
  - path: "` + uprobe + `"
    symbols:
    - "test_2"
`
	err := checkCrd(t, mixed)
	require.Error(t, err)
	require.ErrorContains(t, err, "mixed")
}

func TestUprobeValidationResolvePathInContainerAllowsBinaryDigests(t *testing.T) {
	// binaryDigests is verified per-container against the resolved in-container
	// binary, so the combination is allowed. The digest itself is checked at
	// attach time, not at policy load, so validation accepts it.
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
  - path: "/usr/bin/app"
    symbols:
    - "main"
    resolvePathInContainer: true
    binaryDigests:
    - "sha256:0000000000000000000000000000000000000000000000000000000000000000"
`
	require.NoError(t, checkCrd(t, crd),
		"resolvePathInContainer may be combined with binaryDigests")

	// The Go validation (used by nok8s builds that skip CRD admission) must also
	// accept it.
	spec := &v1alpha1.TracingPolicySpec{
		PodSelector: &slimv1.LabelSelector{
			MatchLabels: map[string]slimv1.MatchLabelsValue{"app": "sshd"},
		},
		UProbes: []v1alpha1.UProbeSpec{{
			Path:                   "/usr/bin/app",
			Symbols:                []string{"main"},
			ResolvePathInContainer: true,
			BinaryDigests: []string{
				"sha256:0000000000000000000000000000000000000000000000000000000000000000",
			},
		}},
	}
	require.NoError(t, preValidateUprobes(spec))
}

func TestUprobeValidationResolvePathInContainerRejectsOtherSections(t *testing.T) {
	// RIC teardown safety relies on "generic_uprobe" being the only
	// non-enforcer sensor in its collection (see sortSensors): a sibling
	// sensor sorting after it could fail to load after the reconciler
	// registered. Guard the single-section rule that enforces this.
	uprobe := testutils.RepoRootPath("contrib/tester-progs/regs-override")
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
  - path: "` + uprobe + `"
    symbols:
    - "test_1"
    resolvePathInContainer: true
  usdts:
  - path: "` + uprobe + `"
    provider: "test"
    name: "probe"
`
	err := checkCrd(t, crd)
	require.Error(t, err)
	require.ErrorContains(t, err, "multiple sections")
}

func TestUprobeValidationResolvePathInContainerBTFPathAllowed(t *testing.T) {
	uprobe := testutils.RepoRootPath("contrib/tester-progs/regs-override")
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
  - path: "` + uprobe + `"
    btfPath: "/usr/lib/btf/payload.btf"
    symbols:
    - "test_1"
    resolvePathInContainer: true
`
	require.NoError(t, checkCrd(t, crd),
		"resolvePathInContainer with btfPath must be accepted")
}

func TestUprobeValidationMultiplePreloadArguments(t *testing.T) {

	// Using multiple preload arguments

	uprobe := testutils.RepoRootPath("contrib/tester-progs/usdt-override")
	crd := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "uprobe"
spec:
  uprobes:
  - path: "` + uprobe + `"
    symbols:
    - "test_3"
    data:
    - index: 0
      type: "string"
      source: "pt_regs"
      resolve: "rdi"
    - index: 1
      type: "string"
      source: "pt_regs"
      resolve: "rsi"
`

	err := checkCrd(t, crd)
	require.Error(t, err)
}
