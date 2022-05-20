// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package ringbufmetrics

import (
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	ringbufPerfEventReceived = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:        consts.MetricNamePrefix + "ringbuf_perf_event_received",
		Help:        "The total number of Tetragon ringbuf perf events received.",
		ConstLabels: nil,
	}, nil)
	ringbufPerfEventLost = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:        consts.MetricNamePrefix + "ringbuf_perf_event_lost",
		Help:        "The total number of Tetragon ringbuf perf events lost.",
		ConstLabels: nil,
	}, nil)
	ringbufPerfEventErrors = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:        consts.MetricNamePrefix + "ringbuf_perf_event_errors",
		Help:        "The total number of Tetragon ringbuf perf event error count.",
		ConstLabels: nil,
	}, nil)
)

// Get a new handle on the metric for received events
func Received() prometheus.Gauge {
	return ringbufPerfEventReceived.WithLabelValues()
}

// Get a new handle on the metric for received events
func ReceivedSet(val float64) {
	Received().Set(val)
}

// Get a new handle on the metric for lost events
func Lost() prometheus.Gauge {
	return ringbufPerfEventLost.WithLabelValues()
}

// Get a new handle on the metric for lost events
func LostSet(val float64) {
	Lost().Set(val)
}

// Get a new handle on the metric for ringbuf errors
func Errors() prometheus.Gauge {
	return ringbufPerfEventErrors.WithLabelValues()
}

// Get a new handle on the metric for ringbuf errors
func ErrorsSet(val float64) {
	Errors().Set(val)
}
