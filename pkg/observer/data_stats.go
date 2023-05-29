// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package observer

import (
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// Define a counter metric for data event statistics
	DataEventStats = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "data_events_total",
		Help:        "The number of data events by type. For internal use only.",
		ConstLabels: nil,
	}, []string{"event"})
)

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
