// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package kprobemetrics

import (
	"maps"
	"slices"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/metrics/consts"
)

type MergeProbeType int

const (
	MergeProbeTypeEnter MergeProbeType = iota
	MergeProbeTypeExit
)

var mergeProbeTypeLabelValues = map[MergeProbeType]string{
	MergeProbeTypeEnter: "enter",
	MergeProbeTypeExit:  "exit",
}

func (t MergeProbeType) String() string {
	return mergeProbeTypeLabelValues[t]
}

var (
	statusLabel = metrics.ConstrainedLabel{
		Name:   "status",
		Values: []string{"error", "ok"},
	}
	currTypeLabel = metrics.ConstrainedLabel{
		Name:   "curr_type",
		Values: slices.Collect(maps.Values(mergeProbeTypeLabelValues)),
	}
	prevTypeLabel = metrics.ConstrainedLabel{
		Name:   "prev_type",
		Values: slices.Collect(maps.Values(mergeProbeTypeLabelValues)),
	}

	MergeTotal = metrics.MustNewCounter(
		metrics.NewOpts(
			consts.MetricsNamespace, "", "generic_kprobe_merge_total",
			"The total number of attempts to merge a kprobe and kretprobe event.",
			nil,
			[]metrics.ConstrainedLabel{statusLabel, currTypeLabel, prevTypeLabel},
			[]metrics.UnconstrainedLabel{{Name: "curr_fn", ExampleValue: consts.ExampleKprobeLabel}, {Name: "prev_fn", ExampleValue: consts.ExampleKprobeLabel}},
		),
		nil,
	)
	MergePushed = metrics.MustNewCounter(metrics.NewOpts(
		consts.MetricsNamespace, "", "generic_kprobe_merge_pushed_total",
		"The total number of pushed events for later merge.",
		nil, nil, nil,
	), nil)
)

func RegisterMetrics(group metrics.Group) {
	group.MustRegister(MergeTotal)
	group.MustRegister(MergePushed)
}

func InitMetricsForDocs() {
	// Initialize metrics with example labels
	for _, curr := range mergeProbeTypeLabelValues {
		for _, prev := range mergeProbeTypeLabelValues {
			for _, status := range []string{"error", "ok"} {
				MergeTotal.WithLabelValues(status, curr, prev, consts.ExampleKprobeLabel, consts.ExampleKprobeLabel).Add(0)
			}
		}
	}
}

// GetMergeTotal returns a handle on the MergeTotal metric
func GetMergeTotal(status string, currFn, prevFn string, currType, prevType MergeProbeType) prometheus.Counter {
	return MergeTotal.WithLabelValues(status, currType.String(), prevType.String(), currFn, prevFn)
}

// MergeErrorsInc increments the merge metric with status error
func MergeErrorsInc(currFn, prevFn string, currType, prevType MergeProbeType) {
	GetMergeTotal("error", currFn, prevFn, currType, prevType).Inc()
}

// MergeOkInc increments the merge metric with status ok
func MergeOkInc(currFn, prevFn string, currType, prevType MergeProbeType) {
	GetMergeTotal("ok", currFn, prevFn, currType, prevType).Inc()
}

// MergePushedInc increments the pushed counter
func MergePushedInc() {
	MergePushed.WithLabelValues().Inc()
}

// ReportMergeOk reports a successful merge
func ReportMergeOk(currFn, prevFn string, currIsReturn, prevIsReturn bool) {
	currType := MergeProbeTypeEnter
	if currIsReturn {
		currType = MergeProbeTypeExit
	}
	prevType := MergeProbeTypeEnter
	if prevIsReturn {
		prevType = MergeProbeTypeExit
	}
	MergeOkInc(currFn, prevFn, currType, prevType)
}

// ReportMergeError reports a merge error
func ReportMergeError(currFn, prevFn string, currIsReturn, prevIsReturn bool) {
	currType := MergeProbeTypeEnter
	if currIsReturn {
		currType = MergeProbeTypeExit
	}
	prevType := MergeProbeTypeEnter
	if prevIsReturn {
		prevType = MergeProbeTypeExit
	}
	MergeErrorsInc(currFn, prevFn, currType, prevType)
}

// TotalMergeStatus returns the total count for a given status
func TotalMergeStatus(status string) uint64 {
	var total uint64
	ch := make(chan prometheus.Metric)
	go func() {
		MergeTotal.Collect(ch)
		close(ch)
	}()
	for m := range ch {
		var d dto.Metric
		m.Write(&d)
		isMatch := false
		for _, lp := range d.Label {
			if lp.Name != nil && *lp.Name == "status" && lp.Value != nil && *lp.Value == status {
				isMatch = true
				break
			}
		}
		if isMatch && d.Counter != nil && d.Counter.Value != nil {
			total += uint64(*d.Counter.Value)
		}
	}
	return total
}
