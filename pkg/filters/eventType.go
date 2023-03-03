// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package filters

import (
	"context"

	"github.com/cilium/tetragon/api/v1/tetragon"
	v1 "github.com/cilium/tetragon/pkg/oldhubble/api/v1"
	hubbleFilters "github.com/cilium/tetragon/pkg/oldhubble/filters"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func filterByEventType(types []tetragon.EventType) hubbleFilters.FilterFunc {
	return func(ev *v1.Event) bool {
		switch event := ev.Event.(type) {
		case *tetragon.GetEventsResponse:
			eventProtoNum := tetragon.EventType_UNDEF

			rft := event.ProtoReflect()
			rft.Range(func(eventDesc protoreflect.FieldDescriptor, v protoreflect.Value) bool {
				if eventDesc.ContainingOneof() == nil || !rft.Has(eventDesc) {
					return true
				}

				eventProtoNum = tetragon.EventType(eventDesc.Number())
				return false
			})

			for _, t := range types {
				if t == eventProtoNum {
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
		fs = append(fs, filterByEventType(ff.EventSet))
	}
	return fs, nil
}
