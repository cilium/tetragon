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
	"github.com/cilium/tetragon/pkg/option"
)

func filterByBinaryRegex(binaryPatterns []string, level int) (hubbleFilters.FilterFunc, error) {
	var binaries []*regexp.Regexp
	for _, pattern := range binaryPatterns {
		query, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to compile regexp: %v", err)
		}
		binaries = append(binaries, query)
	}
	return func(ev *v1.Event) bool {
		var processes []*tetragon.Process
		switch level {
		case 0: // Process
			processes = append(processes, GetProcess(ev))
		case 1: // Parent
			processes = append(processes, GetParent(ev))
		case 2: // Ancestors
			processes = GetAncestors(ev)
		}
		if processes == nil || processes[0] == nil {
			return false
		}
		for _, process := range processes {
			for _, binary := range binaries {
				if binary.MatchString(process.Binary) {
					return true
				}
			}
		}
		return false
	}, nil
}

type BinaryRegexFilter struct{}

func (f *BinaryRegexFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]hubbleFilters.FilterFunc, error) {
	var fs []hubbleFilters.FilterFunc
	if ff.BinaryRegex != nil {
		filters, err := filterByBinaryRegex(ff.BinaryRegex, 0) // 0 - Process
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
		filters, err := filterByBinaryRegex(ff.ParentBinaryRegex, 1) // 1 - Parent
		if err != nil {
			return nil, err
		}
		fs = append(fs, filters)
	}
	return fs, nil
}

type AncestorBinaryRegexFilter struct{}

func (f *AncestorBinaryRegexFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]hubbleFilters.FilterFunc, error) {
	var fs []hubbleFilters.FilterFunc
	if ff.AncestorBinaryRegex != nil {
		// Enable ancestor filter only if --enable-process-ancestors flag is set
		if !option.Config.EnableProcessAncestors {
			return nil, fmt.Errorf("ancestors are not enabled in process events, cannot configure ancestor filter")
		}

		filters, err := filterByBinaryRegex(ff.AncestorBinaryRegex, 2) // 2 - Ancestors
		if err != nil {
			return nil, err
		}
		fs = append(fs, filters)
	}
	return fs, nil
}
