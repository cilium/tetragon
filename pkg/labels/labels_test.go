// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package labels

import (
	"fmt"
	"testing"

	slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/stretchr/testify/require"
)

type testLabel struct {
	labels      Labels
	expectedRes bool
	namespace   string
}

type testCase struct {
	labelSelector *slimv1.LabelSelector
	tests         []testLabel
}

func TestLabels(t *testing.T) {
	testCases := []testCase{
		{
			// empty label selector should match everything
			labelSelector: &slimv1.LabelSelector{},
			tests: []testLabel{
				{map[string]string{"app": "tetragon"}, true, "default"},
				{Labels{}, true, "default"},
			},
		}, {
			labelSelector: &slimv1.LabelSelector{
				MatchLabels: map[string]slimv1.MatchLabelsValue{
					"app": "tetragon",
				},
			},
			tests: []testLabel{
				{map[string]string{"app": "tetragon"}, true, "default"},
				{map[string]string{"app": "cilium"}, false, "default"},
			},
		}, {
			labelSelector: &slimv1.LabelSelector{
				MatchExpressions: []slimv1.LabelSelectorRequirement{{
					Key:      "app",
					Operator: "In",
					Values:   []string{"tetragon", "cilium"},
				}},
			},
			tests: []testLabel{
				{map[string]string{"app": "tetragon"}, true, "default"},
				{map[string]string{"app": "cilium"}, true, "default"},
				{map[string]string{"app": "hubble"}, false, "default"},
			},
		}, {
			labelSelector: &slimv1.LabelSelector{
				MatchExpressions: []slimv1.LabelSelectorRequirement{{
					Key:      "app",
					Operator: "NotIn",
					Values:   []string{"tetragon", "cilium"},
				}},
			},
			tests: []testLabel{
				{map[string]string{"app": "tetragon"}, false, "default"},
				{map[string]string{"app": "cilium"}, false, "default"},
				{map[string]string{"app": "hubble"}, true, "default"},
			},
		}, {
			labelSelector: &slimv1.LabelSelector{
				MatchExpressions: []slimv1.LabelSelectorRequirement{{
					Key:      "app",
					Operator: "Exists",
				}},
			},
			tests: []testLabel{
				{map[string]string{"app": "tetragon"}, true, "default"},
				{map[string]string{"application": "cilium"}, false, "default"},
				{map[string]string{"app": "hubble"}, true, "default"},
			},
		}, {
			labelSelector: &slimv1.LabelSelector{
				MatchExpressions: []slimv1.LabelSelectorRequirement{{
					Key:      "app",
					Operator: "DoesNotExist",
				}},
			},
			tests: []testLabel{
				{map[string]string{"app": "tetragon"}, false, "default"},
				{map[string]string{"application": "cilium"}, true, "default"},
				{map[string]string{"app": "hubble"}, false, "default"},
			},
		}, {
			labelSelector: &slimv1.LabelSelector{
				MatchExpressions: []slimv1.LabelSelectorRequirement{{
					Key:      "application",
					Operator: "DoesNotExist",
				}},
				MatchLabels: map[string]slimv1.MatchLabelsValue{
					"app": "tetragon",
				},
			},
			tests: []testLabel{
				{map[string]string{"app": "tetragon"}, true, "default"},
				{map[string]string{"application": "tetragon"}, false, "default"},
				{map[string]string{"app": "tetragon", "application": "tetragon"}, false, "default"},
				{map[string]string{"app": "tetragon", "pizza": "yes"}, true, "default"},
			},
		}, {
			labelSelector: &slimv1.LabelSelector{
				MatchExpressions: []slimv1.LabelSelectorRequirement{{
					Key:      K8sPodNamespace,
					Operator: "In",
					Values:   []string{"tetragon"},
				}},
			},
			tests: []testLabel{
				{map[string]string{K8sPodNamespace: "tetragon"}, true, "tetragon"},
				{map[string]string{K8sPodNamespace: "test"}, false, "default"},
			},
		}, {
			labelSelector: &slimv1.LabelSelector{
				MatchExpressions: []slimv1.LabelSelectorRequirement{{
					Key:      K8sPodNamespace,
					Operator: "In",
					Values:   []string{"cilium", "tetragon"},
				}},
			},
			tests: []testLabel{
				{map[string]string{"app": "tetragon"}, true, "cilium"},
				{map[string]string{"app": "cilium"}, true, "tetragon"},
				{map[string]string{"app": "hubble"}, false, "default"},
			},
		}, {
			labelSelector: &slimv1.LabelSelector{
				MatchExpressions: []slimv1.LabelSelectorRequirement{{
					Key:      K8sPodNamespace,
					Operator: "NotIn",
					Values:   []string{"cilium", "tetragon"},
				}},
			},
			tests: []testLabel{
				{map[string]string{"app": "tetragon"}, false, "cilium"},
				{map[string]string{"app": "cilium"}, false, "tetragon"},
				{map[string]string{"app": "hubble"}, true, "default"},
			},
		}, {
			labelSelector: &slimv1.LabelSelector{
				MatchExpressions: []slimv1.LabelSelectorRequirement{{
					Key:      K8sPodNamespace,
					Operator: "Exists",
				}},
			},
			tests: []testLabel{
				{map[string]string{K8sPodNamespace: "tetragon"}, true, "tetragon"},
				{map[string]string{}, true, ""},
			},
		}, {
			labelSelector: &slimv1.LabelSelector{
				MatchExpressions: []slimv1.LabelSelectorRequirement{{
					Key:      "name",
					Operator: "In",
					Values:   []string{"main", "secondary"},
				}},
			},
			tests: []testLabel{
				{map[string]string{"name": "main"}, true, ""},
				{map[string]string{"name": "secondary"}, true, ""},
				{map[string]string{"name": "init"}, false, ""},
			},
		},
	}

	for _, tc := range testCases {
		selector, err := SelectorFromLabelSelector(tc.labelSelector)
		require.NoError(t, err)
		for _, test := range tc.tests {
			if _, ok := test.labels[K8sPodNamespace]; !ok {
				test.labels[K8sPodNamespace] = test.namespace
			}
			res := selector.Match(test.labels)
			if res != test.expectedRes {
				t.Fatalf("label selector:%+v labels:%+v expected:%t got:%t", tc.labelSelector, test.labels, test.expectedRes, res)
			}
		}
	}
}

type testCmp struct {
	l1, l2   map[string]string
	expected bool
}

func TestCmp(t *testing.T) {

	cases := []testCmp{
		{l1: map[string]string{}, l2: map[string]string{}, expected: false},
		{l1: map[string]string{"label1": "a"}, l2: map[string]string{}, expected: true},
		{l1: map[string]string{"label1": "a"}, l2: map[string]string{"label1": "b"}, expected: true},
		{l1: map[string]string{"label1": "a"}, l2: map[string]string{"label1": "a"}, expected: false},
		{l1: map[string]string{"label1": "a"}, l2: map[string]string{"label2": "a"}, expected: true},
	}

	for _, tc := range cases {
		require.Equal(t, tc.expected, Labels(tc.l1).Cmp(tc.l2), fmt.Sprintf("test: %+v", tc))
		require.Equal(t, tc.expected, Labels(tc.l2).Cmp(tc.l1), fmt.Sprintf("reverse-test: %+v", tc))
	}
}
