package labels

import (
	"fmt"
	"testing"

	slimv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/stretchr/testify/require"
)

type testLabel struct {
	labels      Labels
	expectedRes bool
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
				{map[string]string{"app": "tetragon"}, true},
				{nil, true},
			},
		}, {
			labelSelector: &slimv1.LabelSelector{
				MatchLabels: map[string]slimv1.MatchLabelsValue{
					"app": "tetragon",
				},
			},
			tests: []testLabel{
				{map[string]string{"app": "tetragon"}, true},
				{map[string]string{"app": "cilium"}, false},
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
				{map[string]string{"app": "tetragon"}, true},
				{map[string]string{"app": "cilium"}, true},
				{map[string]string{"app": "hubble"}, false},
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
				{map[string]string{"app": "tetragon"}, false},
				{map[string]string{"app": "cilium"}, false},
				{map[string]string{"app": "hubble"}, true},
			},
		}, {
			labelSelector: &slimv1.LabelSelector{
				MatchExpressions: []slimv1.LabelSelectorRequirement{{
					Key:      "app",
					Operator: "Exists",
				}},
			},
			tests: []testLabel{
				{map[string]string{"app": "tetragon"}, true},
				{map[string]string{"application": "cilium"}, false},
				{map[string]string{"app": "hubble"}, true},
			},
		}, {
			labelSelector: &slimv1.LabelSelector{
				MatchExpressions: []slimv1.LabelSelectorRequirement{{
					Key:      "app",
					Operator: "DoesNotExist",
				}},
			},
			tests: []testLabel{
				{map[string]string{"app": "tetragon"}, false},
				{map[string]string{"application": "cilium"}, true},
				{map[string]string{"app": "hubble"}, false},
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
				{map[string]string{"app": "tetragon"}, true},
				{map[string]string{"application": "tetragon"}, false},
				{map[string]string{"app": "tetragon", "application": "tetragon"}, false},
				{map[string]string{"app": "tetragon", "pizza": "yes"}, true},
			},
		},
	}

	for _, tc := range testCases {
		selector, err := SelectorFromLabelSelector(tc.labelSelector)
		require.NoError(t, err)
		for _, test := range tc.tests {
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
