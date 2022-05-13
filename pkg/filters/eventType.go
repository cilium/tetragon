// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package filters

import (
	"context"
	"reflect"

	v1 "github.com/cilium/hubble/pkg/api/v1"
	hubbleFilters "github.com/cilium/hubble/pkg/filters"
	"github.com/cilium/tetragon/api/v1/tetragon"
	codegen "github.com/cilium/tetragon/api/v1/tetragon/codegen/filters"
)

func filterByEventType(types []reflect.Type) hubbleFilters.FilterFunc {
	return func(ev *v1.Event) bool {
		switch event := ev.Event.(type) {
		case *tetragon.GetEventsResponse:
			r := reflect.TypeOf(event.Event)
			for _, t := range types {
				if t == r {
					return true
				}
			}
		}
		return false
	}
}

type EventTypeFilter struct{}

func (f *EventTypeFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]hubbleFilters.FilterFunc, error) {
	var fs []hubbleFilters.FilterFunc
	if ff.EventSet != nil {
		var types []reflect.Type

		for _, s := range ff.EventSet {
			opCode, err := codegen.OpCodeForEventType(s)
			if err != nil {
				return nil, err
			}
			types = append(types, opCode)
		}
		fs = append(fs, filterByEventType(types))
	}
	return fs, nil
}
