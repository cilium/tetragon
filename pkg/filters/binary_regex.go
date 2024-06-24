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

func filterByBinaryRegex(binaryPatterns []string, parent bool) (hubbleFilters.FilterFunc, error) {
	var binaries []*regexp.Regexp
	for _, pattern := range binaryPatterns {
		query, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to compile regexp: %v", err)
		}
		binaries = append(binaries, query)
	}
	return func(ev *v1.Event) bool {
		var process *tetragon.Process
		if parent {
			process = GetParent(ev)

		} else {
			process = GetProcess(ev)
		}
		if process == nil {
			return false
		}
		for _, binary := range binaries {
			if binary.MatchString(process.Binary) {
				return true
			}
		}
		return false
	}, nil
}

type BinaryRegexFilter struct{}

func (f *BinaryRegexFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]hubbleFilters.FilterFunc, error) {
	var fs []hubbleFilters.FilterFunc
	if ff.BinaryRegex != nil {
		filters, err := filterByBinaryRegex(ff.BinaryRegex, false)
		if err != nil {
			return nil, err
		}
		fs = append(fs, filters)
	}
	return fs, nil
}

type ParentBinaryRegexFilter struct{}

func (f *ParentBinaryRegexFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]hubbleFilters.FilterFunc, error) {
	var fs []hubbleFilters.FilterFunc
	if ff.ParentBinaryRegex != nil {
		filters, err := filterByBinaryRegex(ff.ParentBinaryRegex, true)
		if err != nil {
			return nil, err
		}
		fs = append(fs, filters)
	}
	return fs, nil
}
