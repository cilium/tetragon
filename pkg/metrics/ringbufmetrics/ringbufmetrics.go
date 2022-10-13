// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package ringbufmetrics

import (
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	PerfEventReceived = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:        consts.MetricNamePrefix + "ringbuf_perf_event_received",
		Help:        "The total number of Tetragon ringbuf perf events received.",
		ConstLabels: nil,
	}, nil)
	PerfEventLost = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:        consts.MetricNamePrefix + "ringbuf_perf_event_lost",
		Help:        "The total number of Tetragon ringbuf perf events lost.",
		ConstLabels: nil,
	}, nil)
	PerfEventErrors = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:        consts.MetricNamePrefix + "ringbuf_perf_event_errors",
		Help:        "The total number of Tetragon ringbuf perf event error count.",
		ConstLabels: nil,
	}, nil)
	PerfEventUnknown = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:        consts.MetricNamePrefix + "ringbuf_perf_event_unknown",
		Help:        "The total number of Tetragon ringbuf perf event unknown events.",
		ConstLabels: nil,
	}, nil)
)

// Get a new handle on the metric for received events
func GetReceived() prometheus.Gauge {
	return PerfEventReceived.WithLabelValues()
}

// Get a new handle on the metric for received events
func ReceivedSet(val float64) {
	GetReceived().Set(val)
}

// Get a new handle on the metric for lost events
func GetLost() prometheus.Gauge {
	return PerfEventLost.WithLabelValues()
}

// Get a new handle on the metric for lost events
func LostSet(val float64) {
	GetLost().Set(val)
}

// Get a new handle on the metric for ringbuf errors
func GetErrors() prometheus.Gauge {
	return PerfEventErrors.WithLabelValues()
}

// Get a new handle on the metric for ringbuf errors
func ErrorsSet(val float64) {
	GetErrors().Set(val)
}

// Get a new handle on the metric for ringbuf unknown events
func GetUnknown() prometheus.Gauge {
	return PerfEventUnknown.WithLabelValues()
}

// Get a new handle on the metric for ringbuf unknown events
func UnknownSet(val float64) {
	GetUnknown().Set(val)
}
