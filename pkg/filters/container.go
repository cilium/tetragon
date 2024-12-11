// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package filters

import (
	"context"
	"fmt"
	"regexp"

	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	hubbleFilters "github.com/cilium/cilium/pkg/hubble/filters"
	"github.com/cilium/tetragon/api/v1/tetragon"
)

func filterByContainerID(idPatterns []string) (hubbleFilters.FilterFunc, error) {
	var ids []*regexp.Regexp
	for _, pattern := range idPatterns {
		query, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to compile regexp: %v", err)
		}
		ids = append(ids, query)
	}

	return func(ev *v1.Event) bool {
		process := GetProcess(ev)
		if process == nil {
			return false
		}
		for _, id := range ids {
			if id.MatchString(process.Docker) {
				return true
			}
		}
		return false
	}, nil
}

type ContainerIDFilter struct{}

func (f *ContainerIDFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]hubbleFilters.FilterFunc, error) {
	var fs []hubbleFilters.FilterFunc
	if ff.ContainerId != nil {
		filters, err := filterByContainerID(ff.ContainerId)
		if err != nil {
			return nil, err
		}
		fs = append(fs, filters)
	}
	return fs, nil
}

func filterByInInitTree(inInitTree bool) hubbleFilters.FilterFunc {
	return func(ev *v1.Event) bool {
		process := GetProcess(ev)
		// We want to be safe and assume false if process.InInitTree is missing somehow
		inInitTreeVal := false
		if process.InInitTree != nil {
			inInitTreeVal = process.InInitTree.Value
		}
		return inInitTreeVal == inInitTree
	}
}

type InInitTreeFilter struct{}

func (f *InInitTreeFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]hubbleFilters.FilterFunc, error) {
	var fs []hubbleFilters.FilterFunc
	if ff.InInitTree != nil {
		fs = append(fs, filterByInInitTree(ff.InInitTree.Value))
	}
	return fs, nil
}
