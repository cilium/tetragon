// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package filters

import (
	"context"
	"slices"

	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/cilium/tetragon/api/v1/tetragon"
	pkgEvent "github.com/cilium/tetragon/pkg/event"
)

func filterByEventType(types []tetragon.EventType) FilterFunc {
	return func(ev *pkgEvent.Event) bool {
		switch event := ev.Event.(type) {
		case *tetragon.GetEventsResponse:
			eventProtoNum := tetragon.EventType_UNDEF

			rft := event.ProtoReflect()
			rft.Range(func(eventDesc protoreflect.FieldDescriptor, _ protoreflect.Value) bool {
				if eventDesc.ContainingOneof() == nil || !rft.Has(eventDesc) {
					return true
				}

				eventProtoNum = tetragon.EventType(eventDesc.Number())
				return false
			})

			if slices.Contains(types, eventProtoNum) {
				return true
			}
		}
		return false
	}
}

type EventTypeFilter struct{}

func (f *EventTypeFilter) OnBuildFilter(_ context.Context, ff *tetragon.Filter) ([]FilterFunc, error) {
	var fs []FilterFunc
	if ff.EventSet != nil {
		fs = append(fs, filterByEventType(ff.EventSet))
	}
	return fs, nil
}
