// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracingpolicy

import (
	_ "embed"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/build"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/testutils/tempfile"
)

//go:embed examples/tracepoint-lseek-pid.yaml
var lseekExample string

func TestYamlLseek(t *testing.T) {
	build.SkipIfK8sDisabled(t)
	expected := GenericTracingPolicy{
		APIVersion: "cilium.io/v1alpha1",
		Kind:       "TracingPolicy",
		Metadata:   ObjectMeta{Name: "tracepoint-lseek"},
		Spec: v1alpha1.TracingPolicySpec{
			Tracepoints: []v1alpha1.TracepointSpec{{
				Subsystem: "syscalls",
				Event:     "sys_enter_lseek",
				Args: []v1alpha1.KProbeArg{
					{Index: 7, Type: "auto"},
					{Index: 5, Type: "auto"},
				},
				Selectors: []v1alpha1.KProbeSelector{{
					MatchPIDs: []v1alpha1.PIDSelector{
						{
							Operator:       "In",
							FollowForks:    true,
							IsNamespacePID: false,
							Values:         []uint32{1111},
						},
					},
					MatchArgs: []v1alpha1.ArgSelector{
						{
							Index:    7,
							Operator: "Equal",
							Values:   []string{"4444"},
						},
					},
				}},
			}},
		},
	}

	pol, err := FromYAML(lseekExample)
	if err != nil {
		t.Errorf("YamlData error %s", err)
	}
	k := pol.(*GenericTracingPolicy)
	if err != nil {
		t.Errorf("ReadConfigYaml failed: %s", err)
	}

	if diff := cmp.Diff(expected, *k); diff != "" {
		t.Errorf("mismatch (-expected, +got): %s", diff)
	}
}

const tpNamespaced = `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicyNamespaced
metadata:
  name: "tracepoint-lseek"
  namespace: "default"
spec:
  tracepoints:
  - subsystem: "syscalls"
    event: "sys_enter_lseek"
`

func TestYamlNamespaced(t *testing.T) {
	build.SkipIfK8sDisabled(t)
	tp, err := FromYAML(tpNamespaced)
	require.NoError(t, err)
	require.Equal(t, "default", tp.TpNamespace())
}

func TestEmptyTracingPolicy(t *testing.T) {
	path := tempfile.CreateTempFile(t, "")
	_, err := FromFile(path)
	require.Error(t, err)
}

func TestWrongCaseTracingPolicy(t *testing.T) {
	_, err := FromYAML(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tracepoint-test"
spec:
  Tracepoints: # wrong case
  - subsystem: "syscalls"
    event: "sys_enter_lseek"
`)
	require.Error(t, err)
}

const tpNodeSelector = `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tracepoint-lseek"
spec:
  nodeSelector:
    matchLabels:
      node-role: gpu
    matchExpressions:
      - key: kubernetes.io/arch
        operator: In
        values:
          - amd64
  tracepoints:
  - subsystem: "syscalls"
    event: "sys_enter_lseek"
`

func TestYamlNodeSelector(t *testing.T) {
	build.SkipIfK8sDisabled(t)
	tp, err := FromYAML(tpNodeSelector)
	require.NoError(t, err)
	sel := tp.TpSpec().NodeSelector
	require.NotNil(t, sel, "nodeSelector should be parsed")
	require.Equal(t, "gpu", sel.MatchLabels["node-role"])
	require.Len(t, sel.MatchExpressions, 1)
	require.Equal(t, "kubernetes.io/arch", sel.MatchExpressions[0].Key)
}

const tpLabels = `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tracepoint-lseek"
  labels:
    best-food: pizza
spec:
  tracepoints:
  - subsystem: "syscalls"
    event: "sys_enter_lseek"
`

func TestYamlLabels(t *testing.T) {
	tp, err := FromYAML(tpLabels)
	require.NoError(t, err)
	gtp, ok := tp.(*GenericTracingPolicy)
	require.True(t, ok, "FromYAML should return a GenericTracingPolicy")
	val, ok := gtp.Metadata.Labels["best-food"]
	require.True(t, ok, "key should exist in labels")
	require.Equal(t, "pizza", val, "best food should be pizza")
}

func TestUnknownFieldTracingPolicy(t *testing.T) {
	for name, policy := range map[string]string{
		"top level": `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tracepoint-test"
unknown: true
spec:
  tracepoints:
  - subsystem: "syscalls"
    event: "sys_enter_lseek"
`,
		"metadata": `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tracepoint-test"
  unknown: true
spec:
  tracepoints:
  - subsystem: "syscalls"
    event: "sys_enter_lseek"
`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := FromYAML(policy)
			require.Error(t, err)
		})
	}
}

const tpDefaults = `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "defaults"
spec:
  kprobes:
  - call: "sys_lseek"
    selectors:
    - matchCapabilities:
      - operator: In
        values: ["CAP_SYS_ADMIN"]
  - call: "sys_close"
    syscall:
  - call: "fd_install"
    syscall: false
    args:
    - index: 0
      type: "int"
  tracepoints:
  - subsystem: "raw_syscalls"
    event: "sys_enter"
    args:
    - index: 4
  fentries:
  - call: "sys_close"
  uprobes:
  - path: "/bin/bash"
    addrs: [9007199254740993]
  selectorsMacros:
    caps:
      matchCapabilities:
      - operator: In
        values: ["CAP_SYS_ADMIN"]
`

// The schema defaults apply in every build, as the API server applies them.
func TestYamlDefaults(t *testing.T) {
	tp, err := FromYAML(tpDefaults)
	require.NoError(t, err)
	spec := tp.TpSpec()

	require.True(t, spec.KProbes[0].Syscall)
	require.Equal(t, "Effective", spec.KProbes[0].Selectors[0].MatchCapabilities[0].Type)
	require.Equal(t, "auto", spec.Tracepoints[0].Args[0].Type)
	require.True(t, spec.Fentries[0].Syscall)
	require.Equal(t, "Effective", spec.SelectorsMacros["caps"].MatchCapabilities[0].Type)

	// a null takes the default too
	require.True(t, spec.KProbes[1].Syscall)

	// explicit values stay, and integers above 2^53 stay exact
	require.False(t, spec.KProbes[2].Syscall)
	require.Equal(t, "int", spec.KProbes[2].Args[0].Type)
	require.Equal(t, []uint64{9007199254740993}, spec.UProbes[0].Addrs)
}
