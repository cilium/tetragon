// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package watchermetrics

import (
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

type ErrorType string

const (
	FailedToGetPodError ErrorType = "failed_to_get_pod"
)

var (
	WatcherErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace:   metrics.MetricsNamespace,
		Name:        "watcher_errors",
		Help:        "The total number of errors for a given watcher type.",
		ConstLabels: nil,
	}, []string{"watcher", "error"})
	WatcherEvents = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace:   metrics.MetricsNamespace,
		Name:        "watcher_events",
		Help:        "The total number of events for a given watcher type.",
		ConstLabels: nil,
	}, []string{"watcher"})
)

// Get a new handle on an WatcherEvents metric for a watcher type
func GetWatcherEvents(watcherType string) prometheus.Counter {
	return WatcherEvents.WithLabelValues(watcherType)
}

// Get a new handle on an WatcherEvents metric for a watcher type
func GetWatcherErrors(watcherType string, watcherError ErrorType) prometheus.Counter {
	return WatcherErrors.WithLabelValues(watcherType, string(watcherError))
}
