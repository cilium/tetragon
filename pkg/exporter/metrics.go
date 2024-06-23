// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"io"

	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	eventsExportedTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: consts.MetricsNamespace,
		Name:      "events_exported_total",
		Help:      "Total number of events exported",
	})

	eventsExportedBytesTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: consts.MetricsNamespace,
		Name:      "events_exported_bytes_total",
		Help:      "Number of bytes exported for events",
	})

	eventsExportTimestamp = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: consts.MetricsNamespace,
		Name:      "events_last_exported_timestamp",
		Help:      "Timestamp of the most recent event to be exported",
	})
)

func RegisterMetrics(group metrics.Group) {
	group.MustRegister(eventsExportedTotal)
	group.MustRegister(eventsExportedBytesTotal)
	group.MustRegister(eventsExportTimestamp)
}

func newExportedBytesCounterWriter(w io.Writer, c prometheus.Counter) io.Writer {
	return byteCounterWriter{Writer: w, bytesWritten: c}
}

type byteCounterWriter struct {
	io.Writer
	bytesWritten prometheus.Counter
}

func (w byteCounterWriter) Write(p []byte) (int, error) {
	n, err := w.Writer.Write(p)
	w.bytesWritten.Add(float64(n))
	return n, err
}

func NewExportedBytesTotalWriter(w io.Writer) io.Writer {
	return newExportedBytesCounterWriter(w, eventsExportedBytesTotal)
}
