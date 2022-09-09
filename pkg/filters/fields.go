// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package filters

import (
	"fmt"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/mennanov/fmutils"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// FieldFilter is a helper for filtering fields in events
type FieldFilter struct {
	eventSet []tetragon.EventType
	fields   fmutils.NestedMask
	action   tetragon.FieldFilterAction
}

// NewFieldFilter constructs a new FieldFilter from a set of fields.
func NewFieldFilter(eventSet []tetragon.EventType, fields []string, action tetragon.FieldFilterAction) *FieldFilter {
	return &FieldFilter{
		eventSet: eventSet,
		fields:   fmutils.NestedMaskFromPaths(fields),
		action:   action,
	}
}

// NewIncludeFieldFilter constructs a new inclusion FieldFilter from a set of fields.
func NewIncludeFieldFilter(eventSet []tetragon.EventType, fields []string) *FieldFilter {
	return NewFieldFilter(eventSet, fields, tetragon.FieldFilterAction_INCLUDE)
}

// NewExcludeFieldFilter constructs a new exclusion FieldFilter from a set of fields.
func NewExcludeFieldFilter(eventSet []tetragon.EventType, fields []string) *FieldFilter {
	return NewFieldFilter(eventSet, fields, tetragon.FieldFilterAction_EXCLUDE)
}

// FieldFilterFromProto constructs a new FieldFilter from a Tetragon API field filter.
func FieldFilterFromProto(filter *tetragon.FieldFilter) *FieldFilter {
	var fields fmutils.NestedMask

	if filter.Fields != nil {
		fields = fmutils.NestedMaskFromPaths(filter.Fields.Paths)
	} else {
		fields = make(fmutils.NestedMask)
	}

	return &FieldFilter{
		eventSet: filter.EventSet,
		fields:   fields,
		action:   filter.Action,
	}
}

// FieldFiltersFromGetEventsRequest returns a list of EventFieldFilter for
// a GetEventsRequest.
func FieldFiltersFromGetEventsRequest(request *tetragon.GetEventsRequest) []*FieldFilter {
	var filters []*FieldFilter

	for _, filter := range request.FieldFilters {
		if filter == nil {
			continue
		}
		filters = append(filters, FieldFilterFromProto(filter))
	}

	return filters
}

// Filter filters the fields in the GetEventsResponse, keeping fields specified in the
// inclusion filter and discarding fields specified in the exclusion filter. Exclusion
// takes precedence over inclusion and an empty filter set will keep all remaining fields.
func (f *FieldFilter) Filter(event *tetragon.GetEventsResponse) error {
	if len(f.eventSet) > 0 {
		skipFiltering := true
		eventProtoNum := tetragon.EventType_UNDEF

		rft := event.ProtoReflect()
		rft.Range(func(eventDesc protoreflect.FieldDescriptor, v protoreflect.Value) bool {
			if eventDesc.ContainingOneof() == nil || !rft.Has(eventDesc) {
				return true
			}

			eventProtoNum = tetragon.EventType(eventDesc.Number())
			return false
		})

		for _, t := range f.eventSet {
			if t == eventProtoNum {
				skipFiltering = false
			}
		}

		if skipFiltering {
			return nil
		}
	}

	rft := event.ProtoReflect()
	rft.Range(func(eventDesc protoreflect.FieldDescriptor, _ protoreflect.Value) bool {
		if eventDesc.ContainingOneof() == nil || !rft.Has(eventDesc) {
			return true
		}
		event := rft.Mutable(eventDesc).Message().Interface()
		switch f.action {
		case tetragon.FieldFilterAction_INCLUDE:
			f.fields.Filter(event)
		default:
			f.fields.Prune(event)
		}
		return true
	})

	if !rft.IsValid() {
		return fmt.Errorf("invalid event after field filter")
	}

	return nil
}
