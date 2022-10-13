package buildid

import (
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	BIDStats = promauto.NewCounterVec(prometheus.CounterOpts{
		Name:        consts.MetricNamePrefix + "build_id_stats",
		Help:        "Build ID statistics. For internal use only.",
		ConstLabels: nil,
	}, []string{"count"})
)

type BIDype int

const (
	BIDTypeGetOk BIDype = iota
	BIDTypeGetFail
	BIDTypeSetOk
	BIDTypeSetDup
	BIDTypeMmap2Rcvd
	BIDTypeMmap2Parsed
	BIDTypeRetryFail
	BIDTypeRetryOk
)

var BIDTypeStrings = map[BIDype]string{
	BIDTypeGetOk:       "GetOk",
	BIDTypeGetFail:     "GetFail",
	BIDTypeSetOk:       "SetOk",
	BIDTypeSetDup:      "SetDup",
	BIDTypeMmap2Rcvd:   "Mmap2Rcvd",
	BIDTypeMmap2Parsed: "Mmap2Parsed",
	BIDTypeRetryFail:   "RetryFail",
	BIDTypeRetryOk:     "RetryOk",
}

// Increment a Build Id metric for a retrieval type
func BIDMetricInc(ty BIDype) {
	BIDStats.WithLabelValues(BIDTypeStrings[ty]).Inc()
}
