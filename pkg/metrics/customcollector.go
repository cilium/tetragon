// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

type collectFunc func(chan<- prometheus.Metric)

type customCollector struct {
	metrics            []customMetric
	collectFunc        collectFunc
	collectForDocsFunc collectFunc
}

// NewCustomCollector creates a new customCollector.
//
// If collectForDocs is nil, the collector will use collect function for both
// regular metrics server and generating documentation.
func NewCustomCollector(
	metrics []customMetric, collect collectFunc, collectForDocs collectFunc,
) CollectorWithInit {
	return &customCollector{
		metrics:            metrics,
		collectFunc:        collect,
		collectForDocsFunc: collectForDocs,
	}
}

// Describe implements CollectorWithInit (prometheus.Collector).
func (c *customCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, m := range c.metrics {
		ch <- m.Desc()
	}
}

// Collect implements CollectorWithInit (prometheus.Collector).
func (c *customCollector) Collect(ch chan<- prometheus.Metric) {
	if c.collectFunc != nil {
		c.collectFunc(ch)
	}
}

// IsConstrained implements CollectorWithInit.
func (c *customCollector) IsConstrained() bool {
	for _, m := range c.metrics {
		if !m.IsConstrained() {
			return false
		}
	}
	return true
}

// Init implements CollectorWithInit.
func (c *customCollector) Init() {
	// since metrics are collected independently, there's nothing to initialize
}

// InitForDocs implements CollectorWithInit.
func (c *customCollector) InitForDocs() {
	// override Collect method if there's a separate one for docs
	if c.collectForDocsFunc != nil {
		c.collectFunc = c.collectForDocsFunc
	}
}
