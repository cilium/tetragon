// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metrics

import (
	"fmt"
	"net/http"
	"sync"

	"golang.org/x/exp/slices"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	registry     *prometheus.Registry
	registryOnce sync.Once
)

type GranularCounter struct {
	counter     *prometheus.CounterVec
	CounterOpts prometheus.CounterOpts
	labels      []string
	register    sync.Once
}

func MustNewGranularCounter(opts prometheus.CounterOpts, labels []string) *GranularCounter {
	for _, label := range labels {
		if slices.Contains(consts.KnownMetricLabelFilters, label) {
			panic(fmt.Sprintf("labels passed to GranularCounter can't contain any of the following: %v. These labels are added by Tetragon.", consts.KnownMetricLabelFilters))
		}
	}
	return &GranularCounter{
		CounterOpts: opts,
		labels:      append(labels, consts.KnownMetricLabelFilters...),
	}
}

func (m *GranularCounter) ToProm() *prometheus.CounterVec {
	m.register.Do(func() {
		m.labels = FilterMetricLabels(m.labels...)
		m.counter = NewCounterVecWithPod(m.CounterOpts, m.labels)
	})
	return m.counter
}

func EnableMetrics(address string) {
	reg := GetRegistry()

	logger.GetLogger().WithField("addr", address).Info("Starting metrics server")
	http.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}))
	http.ListenAndServe(address, nil)
}

// The FilterMetricLabels func takes in string arguments and returns a slice of those strings omitting the labels it is not configured for.
// IMPORTANT! The filtered metric labels must be passed last and in the exact order of consts.KnownMetricLabelFilters.
func FilterMetricLabels(labels ...string) []string {
	offset := len(labels) - len(consts.KnownMetricLabelFilters)
	if offset < 0 {
		logger.GetLogger().WithField("labels", labels).Debug("Not enough labels provided to metrics.FilterMetricLabels.")
		return labels
	}
	result := labels[:offset]
	for i, label := range consts.KnownMetricLabelFilters {
		if _, ok := option.Config.MetricsLabelFilter[label]; ok {
			result = append(result, labels[offset+i])
		}
	}
	return result
}
