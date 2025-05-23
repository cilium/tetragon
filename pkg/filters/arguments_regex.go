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

func filterByArgumentsRegex(argumentsPatterns []string, parent bool) (FilterFunc, error) {
	var argsRegexList []*regexp.Regexp
	for _, pattern := range argumentsPatterns {
		query, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to compile regexp: %w", err)
		}
		argsRegexList = append(argsRegexList, query)
	}
	return func(ev *event.Event) bool {
		var process *tetragon.Process
		if parent {
			process = GetParent(ev)
		} else {
			process = GetProcess(ev)
		}
		if process == nil {
			return false
		}
		for _, argRegex := range argsRegexList {
			if argRegex.MatchString(process.Arguments) {
				return true
			}
		}
		return false
	}, nil
}

type ArgumentsRegexFilter struct{}

func (f *ArgumentsRegexFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]FilterFunc, error) {
	var fs []FilterFunc
	if ff.ArgumentsRegex != nil {
		argumentsFilters, err := filterByArgumentsRegex(ff.ArgumentsRegex, false)
		if err != nil {
			return nil, err
		}
		fs = append(fs, argumentsFilters)
	}
	return fs, nil
}

type ParentArgumentsRegexFilter struct{}

func (f *ParentArgumentsRegexFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]FilterFunc, error) {
	var fs []FilterFunc
	if ff.ParentArgumentsRegex != nil {
		argumentsFilters, err := filterByArgumentsRegex(ff.ParentArgumentsRegex, true)
		if err != nil {
			return nil, err
		}
		fs = append(fs, argumentsFilters)
	}
	return fs, nil
}
