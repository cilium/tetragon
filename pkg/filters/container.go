// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package filters

import (
	"context"
	"fmt"
	"regexp"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/event"
)

func filterByContainerID(idPatterns []string) (FilterFunc, error) {
	var ids []*regexp.Regexp
	for _, pattern := range idPatterns {
		query, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to compile regexp: %w", err)
		}
		ids = append(ids, query)
	}

	return func(ev *event.Event) bool {
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

func (f *ContainerIDFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]FilterFunc, error) {
	var fs []FilterFunc
	if ff.ContainerId != nil {
		filters, err := filterByContainerID(ff.ContainerId)
		if err != nil {
			return nil, err
		}
		fs = append(fs, filters)
	}
	return fs, nil
}

func filterByInInitTree(inInitTree bool) FilterFunc {
	return func(ev *event.Event) bool {
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

func (f *InInitTreeFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]FilterFunc, error) {
	var fs []FilterFunc
	if ff.InInitTree != nil {
		fs = append(fs, filterByInInitTree(ff.InInitTree.Value))
	}
	return fs, nil
}

func filterByContainerName(namePatterns []string) (FilterFunc, error) {
	var names []*regexp.Regexp
	for _, pattern := range namePatterns {
		query, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to compile regexp: %w", err)
		}
		names = append(names, query)
	}

	return func(ev *event.Event) bool {
		process := GetProcess(ev)
		if process == nil {
			return false
		}
		if process.Pod == nil {
			return false
		}
		if process.Pod.Container == nil {
			return false
		}
		for _, name := range names {
			if name.MatchString(process.Pod.Container.Name) {
				return true
			}
		}
		return false
	}, nil
}

type ContainerNameFilter struct{}

func (f *ContainerNameFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]FilterFunc, error) {
	var fs []FilterFunc
	if ff.ContainerNameRegex != nil {
		filters, err := filterByContainerName(ff.ContainerNameRegex)
		if err != nil {
			return nil, err
		}
		fs = append(fs, filters)
	}
	return fs, nil
}
