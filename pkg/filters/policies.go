// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package filters

import (
	"context"

	"github.com/cilium/tetragon/api/v1/tetragon"
	v1 "github.com/cilium/tetragon/pkg/oldhubble/api/v1"
	hubbleFilters "github.com/cilium/tetragon/pkg/oldhubble/filters"
)

// filterByPolicyName returns a FilterFunc. The FilterFunc returns true if and only if any of the
// specified policy names select the event.
func filterByPolicyName(values []string) hubbleFilters.FilterFunc {
	return func(ev *v1.Event) bool {
		policyName := GetPolicyName(ev)
		if policyName == "" {
			return false
		}
		for _, v := range values {
			if policyName == v {
				return true
			}
		}
		return false
	}
}

// PolicyNamesFilter implements filtering based on Tetragon policy names
type PolicyNamesFilter struct{}

// OnBuildFilter builds a Tetragon policy name filter
func (f *PolicyNamesFilter) OnBuildFilter(_ context.Context, filter *tetragon.Filter) ([]hubbleFilters.FilterFunc, error) {
	var fs []hubbleFilters.FilterFunc

	if filter.PolicyNames != nil {
		fs = append(fs, filterByPolicyName(filter.PolicyNames))
	}
	return fs, nil
}
