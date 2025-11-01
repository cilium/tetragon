// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package observer

import (
	"maps"
	"slices"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
)

type DataEventOp int

const (
	DataEventOpOk DataEventOp = iota
	DataEventOpBad
)

var dataEventStrings = map[DataEventOp]string{
	DataEventOpOk:  "ok",
	DataEventOpBad: "bad",
}

func (e DataEventOp) String() string {
	return dataEventStrings[e]
}

var (
	// Constrained labels for event and op
	eventLabel = metrics.ConstrainedLabel{
		Name:   "event",
		Values: slices.Collect(maps.Values(DataEventTypeStrings)),
	}
	opLabel = metrics.ConstrainedLabel{
		Name:   "op",
		Values: []string{DataEventOpOk.String(), DataEventOpBad.String()},
	}

	// Define a counter metric for data event statistics
	DataEventStats = metrics.MustNewCounter(
		metrics.NewOpts(
			consts.MetricsNamespace, "", "data_events_total",
			"The number of data events by type. For internal use only.",
			nil, []metrics.ConstrainedLabel{eventLabel}, nil,
		),
		nil,
	)

	DataEventSizeHist = metrics.MustNewHistogram(
		metrics.HistogramOpts{
			Opts: metrics.NewOpts(
				consts.MetricsNamespace, "", "data_event_size",
				"The size of received data events.",
				nil, []metrics.ConstrainedLabel{opLabel}, nil,
			),
			Buckets: prometheus.LinearBuckets(1000, 2000, 20),
		},
		nil,
	)
)

func RegisterMetrics(group metrics.Group) {
	group.MustRegister(DataEventStats)
	group.MustRegister(DataEventSizeHist)
}

func InitMetrics() {
	// Initialize metrics with labels
	for _, ev := range DataEventTypeStrings {
		DataEventStats.WithLabelValues(ev).Add(0)
	}
	DataEventSizeHist.WithLabelValues(DataEventOpOk.String())
	DataEventSizeHist.WithLabelValues(DataEventOpBad.String())
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
	DataEventSizeHist.WithLabelValues(DataEventOpOk.String()).Observe(float64(size))
}

func DataEventMetricSizeBad(size uint32) {
	DataEventSizeHist.WithLabelValues(DataEventOpBad.String()).Observe(float64(size))
}
