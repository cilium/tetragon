// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package filters

import (
	"context"
	"fmt"
	"regexp"

	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	hubbleFilters "github.com/cilium/cilium/pkg/hubble/filters"
	"github.com/cilium/tetragon/api/v1/tetragon"
)

func filterByPodRegex(podPatterns []string) (hubbleFilters.FilterFunc, error) {
	var pods []*regexp.Regexp
	for _, pattern := range podPatterns {
		query, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to compile regexp: %w", err)
		}
		pods = append(pods, query)
	}
	return func(ev *v1.Event) bool {
		process := GetProcess(ev)
		if process == nil {
			return false
		}
		if process.Pod == nil {
			return false
		}
		for _, pod := range pods {
			if pod.MatchString(process.Pod.Name) {
				return true
			}
		}
		return false
	}, nil
}

type PodRegexFilter struct{}

func (f *PodRegexFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]hubbleFilters.FilterFunc, error) {
	var fs []hubbleFilters.FilterFunc
	if ff.PodRegex != nil {
		dnsFilters, err := filterByPodRegex(ff.PodRegex)
		if err != nil {
			return nil, err
		}
		fs = append(fs, dnsFilters)
	}
	return fs, nil
}
