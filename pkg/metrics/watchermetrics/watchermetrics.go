// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package watchermetrics

import (
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

type Watcher int

// TODO: Having only one watcher type, "k8s", makes it not a useful label.
// Maybe "pod" would be more informative.
const (
	K8sWatcher Watcher = iota
)

var watcherTypeLabelValues = map[Watcher]string{
	K8sWatcher: "k8s",
}

func (w Watcher) String() string {
	return watcherTypeLabelValues[w]
}

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

func RegisterMetrics(group metrics.Group) {
	group.MustRegister(WatcherErrors)
	group.MustRegister(WatcherEvents)
}

func InitMetrics() {
	// Initialize metrics with labels
	GetWatcherEvents(K8sWatcher).Add(0)
	GetWatcherErrors(K8sWatcher, FailedToGetPodError).Add(0)
}

// Get a new handle on an WatcherEvents metric for a watcher type
func GetWatcherEvents(watcherType Watcher) prometheus.Counter {
	return WatcherEvents.WithLabelValues(watcherType.String())
}

// Get a new handle on an WatcherEvents metric for a watcher type
func GetWatcherErrors(watcherType Watcher, watcherError ErrorType) prometheus.Counter {
	return WatcherErrors.WithLabelValues(watcherType.String(), string(watcherError))
}
