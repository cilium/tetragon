// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package watchermetrics

import (
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

type ErrorType string

const (
	FailedToGetPodError ErrorType = "failed_to_get_pod"
)

var (
	WatcherErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "watcher_errors_total",
		Help:        "The total number of errors for a given watcher type.",
		ConstLabels: nil,
	}, []string{"watcher", "error"})
	WatcherEvents = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace:   consts.MetricsNamespace,
		Name:        "watcher_events_total",
		Help:        "The total number of events for a given watcher type.",
		ConstLabels: nil,
	}, []string{"watcher"})
)

func InitMetrics(registry *prometheus.Registry) {
	registry.MustRegister(WatcherErrors)
	registry.MustRegister(WatcherEvents)
}

// Get a new handle on an WatcherEvents metric for a watcher type
func GetWatcherEvents(watcherType string) prometheus.Counter {
	return WatcherEvents.WithLabelValues(watcherType)
}

// Get a new handle on an WatcherEvents metric for a watcher type
func GetWatcherErrors(watcherType string, watcherError ErrorType) prometheus.Counter {
	return WatcherErrors.WithLabelValues(watcherType, string(watcherError))
}
