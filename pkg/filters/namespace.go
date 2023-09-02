// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package filters

import (
	"context"

	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	hubbleFilters "github.com/cilium/cilium/pkg/hubble/filters"
	"github.com/cilium/tetragon/api/v1/tetragon"
)

func filterByNamespace(namespaces []string) hubbleFilters.FilterFunc {
	return func(ev *v1.Event) bool {
		process := GetProcess(ev)
		if process == nil {
			return false
		}
		for _, namespace := range namespaces {
			if process.Pod == nil {
				if namespace == "" {
					return true
				}
			} else if namespace == process.Pod.Namespace {
				return true
			}
		}
		return false
	}
}

type NamespaceFilter struct{}

func (f *NamespaceFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]hubbleFilters.FilterFunc, error) {
	var fs []hubbleFilters.FilterFunc
	if ff.Namespace != nil {
		fs = append(fs, filterByNamespace(ff.Namespace))
	}
	return fs, nil
}
