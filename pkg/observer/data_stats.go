package tracing

import (
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// Define a counter metric for data event statistics
	DataEventStats = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        consts.MetricNamePrefix + "data_event_stats",
		Help:        "Data event statistics. For internal use only.",
		ConstLabels: nil,
	}, []string{"event", "location"})
)

type EventType int

const (
	EventReceived EventType = iota
	EventMatched
	EventNotMatched
)

var EventTypeStrings = map[EventType]string{
	EventReceived:   "EventReceived",
	EventMatched:    "EventMatched",
	EventNotMatched: "EventNotMatched",
}

// Increment a data event metric for an event type and location
func DataEventMetricInc(event EventType, location string) {
	DataEventStats.WithLabelValues(EventTypeStrings[event], location).Inc()
}

