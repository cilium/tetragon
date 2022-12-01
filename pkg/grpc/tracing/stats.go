package tracing

import (
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	LoaderStats = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        consts.MetricNamePrefix + "process_loader_stats",
		Help:        "Process Loader event statistics. For internal use only.",
		ConstLabels: nil,
	}, []string{"count"})
)

type LoaderType int

const (
	LoaderReceived LoaderType = iota
	LoaderResolvedImm
	LoaderResolvedRetry
)

var LoaderTypeStrings = map[LoaderType]string{
	LoaderReceived:      "LoaderReceived",
	LoaderResolvedImm:   "LoaderResolvedImm",
	LoaderResolvedRetry: "LoaderResolvedRetry",
}

// Increment a Build Id metric for a retrieval type
func LoaderMetricInc(ty LoaderType) {
	LoaderStats.WithLabelValues(LoaderTypeStrings[ty]).Inc()
}
