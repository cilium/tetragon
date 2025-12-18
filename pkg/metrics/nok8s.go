// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !k8s

package metrics

import "github.com/prometheus/client_golang/prometheus"

// See metricswithpod.go for the k8s implementation
func NewCounterVecWithPod(opts prometheus.CounterOpts, labels []string) *prometheus.CounterVec {
	metric := prometheus.NewCounterVec(opts, labels)
	return metric
}

// See metricswithpod.go for the k8s implementation
func NewCounterVecWithPodV2(opts prometheus.CounterVecOpts) *prometheus.CounterVec {
	metric := prometheus.V2.NewCounterVec(opts)
	return metric
}

// See metricswithpod.go for the k8s implementation
func NewGaugeVecWithPod(opts prometheus.GaugeOpts, labels []string) *prometheus.GaugeVec {
	metric := prometheus.NewGaugeVec(opts, labels)
	return metric
}

// See metricswithpod.go for the k8s implementation
func NewGaugeVecWithPodV2(opts prometheus.GaugeVecOpts) *prometheus.GaugeVec {
	metric := prometheus.V2.NewGaugeVec(opts)
	return metric
}

// See metricswithpod.go for the k8s implementation
func NewHistogramVecWithPod(opts prometheus.HistogramOpts, labels []string) *prometheus.HistogramVec {
	metric := prometheus.NewHistogramVec(opts, labels)
	return metric
}

// See metricswithpod.go for the k8s implementation
func NewHistogramVecWithPodV2(opts prometheus.HistogramVecOpts) *prometheus.HistogramVec {
	metric := prometheus.V2.NewHistogramVec(opts)
	return metric
}
