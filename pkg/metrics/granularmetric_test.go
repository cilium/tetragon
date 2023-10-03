// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/tetragon/pkg/metrics/consts"
)

var (
	sampleCounterOpts = prometheus.CounterOpts{
		Namespace: consts.MetricsNamespace,
		Name:      "test_events_total",
		Help:      "The number of test events",
	}
	sampleSyscallCounterOpts = prometheus.CounterOpts{
		Namespace: consts.MetricsNamespace,
		Name:      "test_syscalls_total",
		Help:      "The number of test syscalls",
	}
)

func TestLabelFilter(t *testing.T) {
	// define label filter and metrics
	sampleLabelFilter := NewLabelFilter(
		consts.KnownMetricLabelFilters,
		map[string]interface{}{
			"namespace": nil,
			"workload":  nil,
			"pod":       nil,
			"binary":    nil,
		},
	)
	sampleCounter, err := NewGranularCounter(sampleLabelFilter, sampleCounterOpts, []string{})
	assert.NoError(t, err)
	sampleSyscallCounter, err := NewGranularCounter(sampleLabelFilter, sampleSyscallCounterOpts, []string{"syscall"})
	assert.NoError(t, err)
	// instantiate the underlying metrics
	sampleCounter.ToProm()
	sampleSyscallCounter.ToProm()
	// check that labels are filtered correctly
	sampleLabelValues := []string{"test-namespace", "test-deployment", "test-deployment-d9jo2", "test-binary"}
	expectedLabelValues := []string{"test-namespace", "test-deployment", "test-deployment-d9jo2", "test-binary"}
	assert.Equal(t, expectedLabelValues, sampleCounter.mustFilter(sampleLabelValues...))
	assert.Equal(t, append([]string{"test-syscall"}, expectedLabelValues...), sampleSyscallCounter.mustFilter(append([]string{"test-syscall"}, sampleLabelValues...)...))

	// define another label filter and metrics
	sampleLabelFilter = NewLabelFilter(
		consts.KnownMetricLabelFilters,
		map[string]interface{}{
			"namespace": nil,
			"workload":  nil,
		},
	)
	sampleCounter, err = NewGranularCounter(sampleLabelFilter, sampleCounterOpts, []string{})
	assert.NoError(t, err)
	sampleSyscallCounter, err = NewGranularCounter(sampleLabelFilter, sampleSyscallCounterOpts, []string{"syscall"})
	assert.NoError(t, err)
	// instantiate the underlying metrics
	sampleCounter.ToProm()
	sampleSyscallCounter.ToProm()
	// check that labels are filtered correctly
	sampleLabelValues = []string{"test-namespace", "test-deployment", "test-deployment-d9jo2", "test-binary"}
	expectedLabelValues = []string{"test-namespace", "test-deployment"}
	assert.Equal(t, expectedLabelValues, sampleCounter.mustFilter(sampleLabelValues...))
	assert.Equal(t, append([]string{"test-syscall"}, expectedLabelValues...), sampleSyscallCounter.mustFilter(append([]string{"test-syscall"}, sampleLabelValues...)...))
}
