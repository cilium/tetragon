// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package errmetrics

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
)

var errMetricsMap Map

var errorMetricsMetric = metrics.MustNewCustomCounter(
	metrics.NewOpts(
		consts.MetricsNamespace, "bpf", "error_metrics_total",
		"The total and type of errors encountered exposed via the BPF error metrics API. Internal use only.",
		nil, nil, []metrics.UnconstrainedLabel{
			{Name: "error", ExampleValue: "22"},
			{Name: "error_name", ExampleValue: "EINVAL"},
			{Name: "file_name", ExampleValue: "bpf_d_path.h"},
			{Name: "line_number", ExampleValue: "166"},
			{Name: "helper_func", ExampleValue: "FnProbeRead"},
		},
	),
)

func NewErrorMetricsCollector() prometheus.Collector {
	return metrics.NewCustomCollector(
		metrics.CustomMetrics{
			errorMetricsMetric,
		},
		collect,
		collectForDocs,
	)
}

func collect(ch chan<- prometheus.Metric) {
	if errMetricsMap.Map == nil {
		mapPath := bpf.MapPath(MapName)
		var err error
		errMetricsMap, err = OpenMap(mapPath)
		if err != nil {
			logger.GetLogger().Error("Error metrics: failed to open the map", "mapPath", mapPath, logfields.Error, err)
			return
		}
	}

	values, err := errMetricsMap.Dump()
	if err != nil {
		logger.GetLogger().Error("Error metrics: failed to read the map", logfields.Error, err)
		return
	}

	for _, value := range values {
		ch <- errorMetricsMetric.MustMetric(
			float64(value.Count),
			strconv.FormatUint(uint64(value.Error), 10),
			value.ErrorName,
			value.FileName,
			strconv.FormatUint(uint64(value.LineNumber), 10),
			value.HelperFunc,
		)
	}
}

func collectForDocs(ch chan<- prometheus.Metric) {
	ch <- errorMetricsMetric.MustMetric(1, "22", "EINVAL", "bpf_d_path.h", "166", "FnProbeRead")
}
