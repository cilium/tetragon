// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package filters

import (
	"context"
	"fmt"
	"regexp"

	"github.com/cilium/tetragon/api/v1/tetragon"
	hubbleV1 "github.com/cilium/tetragon/pkg/oldhubble/api/v1"
	hubbleFilters "github.com/cilium/tetragon/pkg/oldhubble/filters"
)

func filterByArgumentsRegex(argumentsPatterns []string) (hubbleFilters.FilterFunc, error) {
	var argsRegexList []*regexp.Regexp
	for _, pattern := range argumentsPatterns {
		query, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to compile regexp: %v", err)
		}
		argsRegexList = append(argsRegexList, query)
	}
	return func(ev *hubbleV1.Event) bool {
		process := GetProcess(ev)
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

func (f *ArgumentsRegexFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]hubbleFilters.FilterFunc, error) {
	var fs []hubbleFilters.FilterFunc
	if ff.ArgumentsRegex != nil {
		argumentsFilters, err := filterByArgumentsRegex(ff.ArgumentsRegex)
		if err != nil {
			return nil, err
		}
		fs = append(fs, argumentsFilters)
	}
	return fs, nil
}
