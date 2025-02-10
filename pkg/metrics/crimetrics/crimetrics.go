// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package crimetrics

import (
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
)

var (
	CriResolutionsTotal = metrics.MustNewCounter(
		metrics.NewOpts(
			consts.MetricsNamespace,
			"cri_cgidmap", "resolutions_total",
			"number of total cgroup id map (cgidmap) CRI resolutions", nil, nil, nil),
		nil)

	CriResolutionErrorsTotal = metrics.MustNewCounter(
		metrics.NewOpts(
			consts.MetricsNamespace,
			"cri_cgidmap", "resolutions_errors_total",
			"number of cgroup id map (cgidmap) CRI resolutions that failed", nil, nil, nil),
		nil)
)

func RegisterMetrics(group metrics.Group) {
	group.MustRegister(CriResolutionsTotal, CriResolutionErrorsTotal)
}
