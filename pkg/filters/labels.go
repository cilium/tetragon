// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package filters

import (
	"context"
	"fmt"

	k8sLabels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	v1 "github.com/cilium/hubble/pkg/api/v1"
	hubbleFilters "github.com/cilium/hubble/pkg/filters"
	"github.com/cilium/tetragon/api/v1/tetragon"
)

// FilterByLabelSelectors returns a FilterFunc. The FilterFunc returns true if and only if any of the
// specified selectors select the event. The caller specifies how to extract labels from the event.
func FilterByLabelSelectors(labelSelectors []string) (hubbleFilters.FilterFunc, error) {
	selectors := make([]k8sLabels.Selector, 0, len(labelSelectors))
	for _, selector := range labelSelectors {
		s, err := k8sLabels.Parse(selector)
		if err != nil {
			return nil, err
		}
		selectors = append(selectors, s)
	}
	return func(ev *v1.Event) bool {
		process := GetProcess(ev)
		if process == nil || process.Pod == nil {
			return false
		}
		labels := process.Pod.PodLabels
		for _, selector := range selectors {
			if selector.Matches(k8sLabels.Set(labels)) {
				return true
			}
		}
		return false
	}, nil
}

// LabelsFilter implements filtering based on pod labels
type LabelsFilter struct{}

// OnBuildFilter builds a labels filter
func (l *LabelsFilter) OnBuildFilter(ctx context.Context, filter *tetragon.Filter) ([]hubbleFilters.FilterFunc, error) {
	var fs []hubbleFilters.FilterFunc

	if filter.Labels != nil {
		slf, err := FilterByLabelSelectors(filter.Labels)
		if err != nil {
			return nil, fmt.Errorf("invalid pod label filter: %v", err)
		}
		fs = append(fs, slf)
	}
	return fs, nil
}
