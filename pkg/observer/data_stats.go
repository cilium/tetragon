// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package observer

import (
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	// Define a counter metric for data event statistics
	DataEventStats = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "data_events_total",
		Help:        "The number of data events by type. For internal use only.",
		ConstLabels: nil,
	}, []string{"event"})

	DataEventSizeHist = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "data_event_size",
		Help:        "The size of received data events.",
		Buckets:     prometheus.LinearBuckets(1000, 2000, 20),
		ConstLabels: nil,
	}, []string{"op"})
)

func InitMetrics(registry *prometheus.Registry) {
	registry.MustRegister(DataEventStats)
	registry.MustRegister(DataEventSizeHist)
	registry.MustRegister(LostEventStats)
}

type DataEventType int

const (
	DataEventReceived DataEventType = iota
	DataEventAdded
	DataEventAppended
	DataEventMatched
	DataEventNotMatched
	DataEventBad
)

var DataEventTypeStrings = map[DataEventType]string{
	DataEventReceived:   "Received",
	DataEventAdded:      "Added",
	DataEventAppended:   "Appended",
	DataEventMatched:    "Matched",
	DataEventNotMatched: "NotMatched",
	DataEventBad:        "Bad",
}

// Increment a data event metric for an event type and location
func DataEventMetricInc(event DataEventType) {
	DataEventStats.WithLabelValues(DataEventTypeStrings[event]).Inc()
}

func DataEventMetricSizeOk(size uint32) {
	DataEventSizeHist.WithLabelValues("ok").Observe(float64(size))
}

func DataEventMetricSizeBad(size uint32) {
	DataEventSizeHist.WithLabelValues("bad").Observe(float64(size))
}
