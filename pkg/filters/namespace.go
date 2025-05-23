// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package filters

import (
	"context"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/event"
)

func filterByNamespace(namespaces []string) FilterFunc {
	return func(ev *event.Event) bool {
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

func (f *NamespaceFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]FilterFunc, error) {
	var fs []FilterFunc
	if ff.Namespace != nil {
		fs = append(fs, filterByNamespace(ff.Namespace))
	}
	return fs, nil
}
