// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracingpolicy

import (
	_ "embed"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/tetragon/pkg/crdutils"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

//go:embed examples/tracepoint-lseek-pid.yaml
var lseekExample string

func TestYamlLseek(t *testing.T) {

	expected := GenericTracingPolicy{
		TypeMeta: v1.TypeMeta{
			APIVersion: "cilium.io/v1alpha1",
			Kind:       "TracingPolicy",
		},
		Metadata: v1.ObjectMeta{Name: "tracepoint-lseek"},
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

	if reflect.DeepEqual(expected, *k) != true {
		t.Errorf("\ngot:\n%+v\nexpected:\n%+v", *k, expected)
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
	tp, err := FromYAML(tpNamespaced)
	require.NoError(t, err)
	_, ok := tp.(TracingPolicyNamespaced)
	require.True(t, ok)
}

func TestEmptyTracingPolicy(t *testing.T) {
	path := crdutils.CreateTempFile(t, "")
	_, err := FromFile(path)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown CRD kind: ")
}
