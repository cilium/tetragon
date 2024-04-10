// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metrics

import (
	"maps"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/cilium/tetragon/pkg/option"
)

func TestProcessLabels(t *testing.T) {
	t.Cleanup(func() {
		// reset global config back to the default
		option.Config.MetricsLabelFilter = maps.Clone(consts.DefaultLabelsFilter)
	})

	namespace := "test-namespace"
	workload := "test-deployment"
	pod := "test-deployment-d9jo2"
	binary := "test-binary"

	// by default all labels should be enabled
	processLabels := NewProcessLabels(namespace, workload, pod, binary)
	assert.Equal(t, processLabels.Values(), []string{namespace, workload, pod, binary})

	// disable workload and pod
	option.Config.MetricsLabelFilter["workload"] = false
	option.Config.MetricsLabelFilter["pod"] = false
	processLabels = NewProcessLabels(namespace, workload, pod, binary)
	assert.Equal(t, processLabels.Values(), []string{namespace, "", "", binary})

	// delete binary (this shouldn't really happen, we set the values to false instead)
	delete(option.Config.MetricsLabelFilter, "binary")
	processLabels = NewProcessLabels(namespace, workload, pod, binary)
	assert.Equal(t, processLabels.Values(), []string{namespace, "", "", ""})

	// disable all
	for l := range consts.DefaultLabelsFilter {
		option.Config.MetricsLabelFilter[l] = false
	}
	processLabels = NewProcessLabels(namespace, workload, pod, binary)
	assert.Equal(t, processLabels.Values(), []string{"", "", "", ""})

	// clear label filter (this shouldn't really happen, we set the values to false instead)
	option.Config.MetricsLabelFilter = map[string]bool{}
	processLabels = NewProcessLabels(namespace, workload, pod, binary)
	assert.Equal(t, processLabels.Values(), []string{"", "", "", ""})
}
