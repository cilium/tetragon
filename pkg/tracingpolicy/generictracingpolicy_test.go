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
	slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/tetragon/pkg/testutils/tempfile"
)

//go:embed examples/tracepoint-lseek-pid.yaml
var lseekExample string

func TestYamlLseek(t *testing.T) {
	build.SkipIfK8sDisabled(t)
	expected := GenericTracingPolicy{
		TypeMeta: TypeMeta{
			APIVersion: "cilium.io/v1alpha1",
			Kind:       "TracingPolicy",
		},
		Metadata: ObjectMeta{Name: "tracepoint-lseek"},
		Spec: v1alpha1.TracingPolicySpec{
			PodSelector:       &slimv1.LabelSelector{},
			ContainerSelector: &slimv1.LabelSelector{},
			HostSelector:      &slimv1.LabelSelector{},
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
	_, ok := tp.(TracingPolicyNamespaced)
	require.True(t, ok)
}

func TestEmptyTracingPolicy(t *testing.T) {
	path := tempfile.CreateTempFile(t, "")
	_, err := FromFile(path)
	require.Error(t, err)
}
