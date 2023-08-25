// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"context"

	pb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/tetragon/pkg/oldhubble/api/v1"
)

func filterByEventType(types []*pb.EventTypeFilter) FilterFunc {
	return func(ev *v1.Event) bool {
		event := ev.GetFlow().GetEventType()
		if event == nil {
			return false
		}

		for _, typeFilter := range types {
			if t := typeFilter.GetType(); t != 0 && event.Type != t {
				continue
			}

			if typeFilter.GetMatchSubType() && typeFilter.GetSubType() != event.SubType {
				continue
			}

			return true
		}

		return false
	}
}

// EventTypeFilter implements filtering based on event type
type EventTypeFilter struct{}

// OnBuildFilter builds an event type filter
func (e *EventTypeFilter) OnBuildFilter(_ context.Context, ff *pb.FlowFilter) ([]FilterFunc, error) {
	var fs []FilterFunc

	types := ff.GetEventType()
	if len(types) > 0 {
		fs = append(fs, filterByEventType(types))
	}

	return fs, nil
}
