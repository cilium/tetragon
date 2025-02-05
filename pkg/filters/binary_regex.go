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

const (
	processBinary = iota
	parentBinary
	ancestorBinary
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
		case processBinary:
			processes = append(processes, GetProcess(ev))
		case parentBinary:
			processes = append(processes, GetParent(ev))
		case ancestorBinary:
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
		filters, err := filterByBinaryRegex(ff.BinaryRegex, processBinary)
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
		filters, err := filterByBinaryRegex(ff.ParentBinaryRegex, parentBinary)
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
		if err := CheckAncestorsEnabled(ff.EventSet); err != nil {
			return nil, err
		}

		filters, err := filterByBinaryRegex(ff.AncestorBinaryRegex, ancestorBinary)
		if err != nil {
			return nil, err
		}
		fs = append(fs, filters)
	}
	return fs, nil
}
