// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package filters

import (
	"context"
	"slices"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/event"
)

// filterByPolicyName returns a FilterFunc. The FilterFunc returns true if and only if any of the
// specified policy names select the event.
func filterByPolicyName(values []string) FilterFunc {
	return func(ev *event.Event) bool {
		policyName := GetPolicyName(ev)
		if policyName == "" {
			return false
		}
		return slices.Contains(values, policyName)
	}
}

// PolicyNamesFilter implements filtering based on Tetragon policy names
type PolicyNamesFilter struct{}

// OnBuildFilter builds a Tetragon policy name filter
func (f *PolicyNamesFilter) OnBuildFilter(_ context.Context, filter *tetragon.Filter) ([]FilterFunc, error) {
	var fs []FilterFunc

	if filter.PolicyNames != nil {
		fs = append(fs, filterByPolicyName(filter.PolicyNames))
	}
	return fs, nil
}
