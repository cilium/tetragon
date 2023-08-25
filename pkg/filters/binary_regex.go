// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package filters

import (
	"context"
	"fmt"
	"regexp"

	"github.com/cilium/tetragon/api/v1/tetragon"
	v1 "github.com/cilium/tetragon/pkg/oldhubble/api/v1"
	hubbleFilters "github.com/cilium/tetragon/pkg/oldhubble/filters"
)

func filterByBinaryRegex(binaryPatterns []string) (hubbleFilters.FilterFunc, error) {
	var binaries []*regexp.Regexp
	for _, pattern := range binaryPatterns {
		query, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to compile regexp: %v", err)
		}
		binaries = append(binaries, query)
	}
	return func(ev *v1.Event) bool {
		process := GetProcess(ev)
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
		dnsFilters, err := filterByBinaryRegex(ff.BinaryRegex)
		if err != nil {
			return nil, err
		}
		fs = append(fs, dnsFilters)
	}
	return fs, nil
}
