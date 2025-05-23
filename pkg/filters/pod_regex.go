// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package filters

import (
	"context"
	"fmt"
	"regexp"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/event"
)

func filterByPodRegex(podPatterns []string) (FilterFunc, error) {
	var pods []*regexp.Regexp
	for _, pattern := range podPatterns {
		query, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to compile regexp: %w", err)
		}
		pods = append(pods, query)
	}
	return func(ev *event.Event) bool {
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

func (f *PodRegexFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]FilterFunc, error) {
	var fs []FilterFunc
	if ff.PodRegex != nil {
		dnsFilters, err := filterByPodRegex(ff.PodRegex)
		if err != nil {
			return nil, err
		}
		fs = append(fs, dnsFilters)
	}
	return fs, nil
}
