// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metrics_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/option"
)

func TestProcessLabels(t *testing.T) {
	t.Cleanup(func() {
		// reset global config back to the default
		option.Config.MetricsLabelFilter = option.DefaultLabelFilter()
	})

	namespace := "test-namespace"
	workload := "test-deployment"
	pod := "test-deployment-d9jo2"
	binary := "test-binary"
	nodeName := "test-node"

	// by default all labels should be enabled
	processLabels := option.CreateProcessLabels(namespace, workload, pod, binary, nodeName)
	assert.Equal(t, []string{namespace, workload, pod, binary, nodeName}, processLabels.Values())

	// disable workload and pod
	option.Config.MetricsLabelFilter["workload"] = false
	option.Config.MetricsLabelFilter["pod"] = false
	processLabels = option.CreateProcessLabels(namespace, workload, pod, binary, nodeName)
	assert.Equal(t, []string{namespace, "", "", binary, nodeName}, processLabels.Values())

	// delete binary (this shouldn't really happen, we set the values to false instead)
	delete(option.Config.MetricsLabelFilter, "binary")
	processLabels = option.CreateProcessLabels(namespace, workload, pod, binary, nodeName)
	assert.Equal(t, []string{namespace, "", "", "", nodeName}, processLabels.Values())

	// disable all
	option.Config.MetricsLabelFilter = option.DefaultLabelFilter()
	for l := range option.Config.MetricsLabelFilter {
		option.Config.MetricsLabelFilter[l] = false
	}
	processLabels = option.CreateProcessLabels(namespace, workload, pod, binary, nodeName)
	assert.Equal(t, []string{"", "", "", "", ""}, processLabels.Values())

	// clear label filter (this shouldn't really happen, we set the values to false instead)
	option.Config.MetricsLabelFilter = metrics.LabelFilter{}
	processLabels = option.CreateProcessLabels(namespace, workload, pod, binary, nodeName)
	assert.Equal(t, []string{"", "", "", "", ""}, processLabels.Values())
}
