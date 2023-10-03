// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metrics_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/option"
)

func TestFilterMetricLabels(t *testing.T) {
	option.Config.MetricsLabelFilter = map[string]interface{}{
		"namespace": nil,
		"workload":  nil,
		"pod":       nil,
		"binary":    nil,
	}
	assert.Equal(t, []string{"type", "namespace", "workspace", "pod", "binary"}, metrics.FilterMetricLabels("type", "namespace", "workspace", "pod", "binary"))
	assert.Equal(t, []string{"syscall", "namespace", "workspace", "pod", "binary"}, metrics.FilterMetricLabels("syscall", "namespace", "workspace", "pod", "binary"))
	assert.Equal(t, []string{"namespace", "workspace", "pod", "binary"}, metrics.FilterMetricLabels("namespace", "workspace", "pod", "binary"))

	option.Config.MetricsLabelFilter = map[string]interface{}{
		"namespace": nil,
		"workload":  nil,
	}
	assert.Equal(t, []string{"type", "namespace", "workspace"}, metrics.FilterMetricLabels("type", "namespace", "workspace", "pod", "binary"))
	assert.Equal(t, []string{"syscall", "namespace", "workspace"}, metrics.FilterMetricLabels("syscall", "namespace", "workspace", "pod", "binary"))
	assert.Equal(t, []string{"namespace", "workspace"}, metrics.FilterMetricLabels("namespace", "workspace", "pod", "binary"))

	option.Config.MetricsLabelFilter = map[string]interface{}{
		"namespace": nil,
		"workload":  nil,
		"pod":       nil,
		"binary":    nil,
	}
	assert.Equal(t, []string{"type", "syscall"}, metrics.FilterMetricLabels("type", "syscall"))
}
