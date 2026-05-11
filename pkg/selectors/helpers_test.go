// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package selectors

import (
	"testing"

	"github.com/stretchr/testify/assert"

	slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"
)

func TestMatchAll(t *testing.T) {
	assert.True(t, MatchAllLabelSelector(&slimv1.LabelSelector{}))
	assert.True(t, MatchAllLabelSelector(&slimv1.LabelSelector{
		MatchLabels: map[string]slimv1.MatchLabelsValue{},
	}))
	assert.True(t, MatchAllLabelSelector(&slimv1.LabelSelector{
		MatchExpressions: []slimv1.LabelSelectorRequirement{},
	}))
	assert.True(t, MatchAllLabelSelector(&slimv1.LabelSelector{
		MatchLabels:      map[string]slimv1.MatchLabelsValue{},
		MatchExpressions: []slimv1.LabelSelectorRequirement{},
	}))
	assert.False(t, MatchAllLabelSelector(nil))
	assert.False(t, MatchAllLabelSelector(&slimv1.LabelSelector{
		MatchLabels: map[string]slimv1.MatchLabelsValue{
			"a": "b",
		},
	}))
	assert.False(t, MatchAllLabelSelector(&slimv1.LabelSelector{
		MatchExpressions: []slimv1.LabelSelectorRequirement{
			{
				Key:      "a",
				Operator: "In",
				Values: []string{
					"b",
				},
			},
		},
	}))
	assert.False(t, MatchAllLabelSelector(&slimv1.LabelSelector{
		MatchLabels: map[string]slimv1.MatchLabelsValue{
			"a": "b",
		},
		MatchExpressions: []slimv1.LabelSelectorRequirement{
			{
				Key:      "a",
				Operator: "In",
				Values: []string{
					"b",
				},
			},
		},
	}))

}
