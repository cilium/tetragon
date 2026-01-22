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

func filterByNamespaceRegex(namespacePatterns []string) (FilterFunc, error) {
	var namespaces []*regexp.Regexp
	for _, pattern := range namespacePatterns {
		query, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("failed to compile regexp: %w", err)
		}
		namespaces = append(namespaces, query)
	}
	return func(ev *event.Event) bool {
		process := GetProcess(ev)
		if process == nil {
			return false
		}
		if process.Pod == nil {
			return false
		}
		for _, ns := range namespaces {
			if ns.MatchString(process.Pod.Namespace) {
				return true
			}
		}
		return false
	}, nil
}

type NamespaceRegexFilter struct{}

func (f *NamespaceRegexFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]FilterFunc, error) {
	var fs []FilterFunc
	if ff.NamespaceRegex != nil {
		filters, err := filterByNamespaceRegex(ff.NamespaceRegex)
		if err != nil {
			return nil, err
		}
		fs = append(fs, filters)
	}
	return fs, nil
}
