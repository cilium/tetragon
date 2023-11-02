// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package filters

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/mennanov/fmutils"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func ParseFieldFilterList(filters string) ([]*tetragon.FieldFilter, error) {
	if filters == "" {
		return nil, nil
	}
	// protobuf does not support paths with _ in them to be defined in JSON representation
	// of FieldMasks. This is a problem for us because our canonical representation of
	// fields is in snake_case and we don't want to create confusion. So we can use a JSON
	// marshalling hack to convert the field names to their camelCase representation
	// before unmarshalling here.
	filters = fixupFieldFilterString(filters)
	dec := json.NewDecoder(strings.NewReader(filters))
	var results []*tetragon.FieldFilter
	for {
		var result tetragon.FieldFilter
		if err := dec.Decode(&result); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		results = append(results, &result)
	}
	return results, nil
}

// Converts a string to snake case.
func fixupSnakeCaseString(s string) string {
	var builder strings.Builder

	for i, r := range s {
		if s[i] == '_' {
			continue
		}
		if i != 0 && s[i-1] == '_' {
			r = unicode.ToUpper(r)
		}
		builder.WriteRune(r)
	}

	return builder.String()
}

// Fixes up a field filter's string representation so that protobuf can unmarshal it from
// JSON.
func fixupFieldFilterString(s string) string {
	var dat map[string]interface{}
	json.Unmarshal([]byte(s), &dat)

	var fields string
	var ok bool
	fields, ok = dat["fields"].(string)
	if !ok {
		return s
	}
	dat["fields"] = fixupSnakeCaseString(fields)

	b, _ := json.Marshal(&dat)
	return string(b)
}

// FieldFilter is a helper for filtering fields in events
type FieldFilter struct {
	eventSet       []tetragon.EventType
	fields         fmutils.NestedMask
	action         tetragon.FieldFilterAction
	invertEventSet bool
	needsCopy      map[tetragon.EventType]struct{}
}

// NewFieldFilter constructs a new FieldFilter from a set of fields.
func NewFieldFilter(eventSet []tetragon.EventType, fields []string, action tetragon.FieldFilterAction, invertEventSet bool) *FieldFilter {
	// We only need to copy exec and exit events when they are explicitly filtering out
	// the PID. This is because we need the PID to not be nil when accessing the event
	// later on from the eventcache. See additional comments below for details.
	var maybeNeedsCopy bool
	if action == tetragon.FieldFilterAction_EXCLUDE {
		for _, field := range fields {
			if strings.HasPrefix(field, "process") {
				maybeNeedsCopy = true
				break
			}
		}
	} else if action == tetragon.FieldFilterAction_INCLUDE {
		// For inclusion, it's the opposite situation from the above. If the process.pid
		// field is NOT present, it will be trimmed. So assume we need a copy unless we
		// see process.pid.
		maybeNeedsCopy = true
		for _, field := range fields {
			if field == "process.pid" {
				maybeNeedsCopy = false
				break
			}
		}
	}

	needsCopy := make(map[tetragon.EventType]struct{})
	if maybeNeedsCopy {
		for _, t := range eventSet {
			needsCopy[t] = struct{}{}
		}
	}

	return &FieldFilter{
		eventSet:       eventSet,
		fields:         fmutils.NestedMaskFromPaths(fields),
		action:         action,
		invertEventSet: invertEventSet,
		needsCopy:      needsCopy,
	}
}

// NewIncludeFieldFilter constructs a new inclusion FieldFilter from a set of fields.
func NewIncludeFieldFilter(eventSet []tetragon.EventType, fields []string, invertEventSet bool) *FieldFilter {
	return NewFieldFilter(eventSet, fields, tetragon.FieldFilterAction_INCLUDE, invertEventSet)
}

// NewExcludeFieldFilter constructs a new exclusion FieldFilter from a set of fields.
func NewExcludeFieldFilter(eventSet []tetragon.EventType, fields []string, invertEventSet bool) *FieldFilter {
	return NewFieldFilter(eventSet, fields, tetragon.FieldFilterAction_EXCLUDE, invertEventSet)
}

// FieldFilterFromProto constructs a new FieldFilter from a Tetragon API field filter.
func FieldFilterFromProto(filter *tetragon.FieldFilter) *FieldFilter {
	var fields []string

	if filter.Fields != nil {
		fields = filter.Fields.Paths
	}

	invert := false
	if filter.InvertEventSet != nil {
		invert = filter.InvertEventSet.Value
	}

	return NewFieldFilter(filter.EventSet, fields, filter.Action, invert)
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

func (f *FieldFilter) NeedsCopy(ev *tetragon.GetEventsResponse) bool {
	_, ok := f.needsCopy[ev.EventType()]
	return ok
}

// Filter filters the fields in the GetEventsResponse, keeping fields specified in the
// inclusion filter and discarding fields specified in the exclusion filter. Exclusion
// takes precedence over inclusion and an empty filter set will keep all remaining fields.
func (f *FieldFilter) Filter(event *tetragon.GetEventsResponse) error {
	if len(f.eventSet) > 0 {
		// skip filtering by default unless the event set is inverted, in which case we
		// want to filter by default and skip only if we have a match
		skipFiltering := !f.invertEventSet
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
				// skip filtering if event set is inverted and we have a match, otherwise
				// don't skip filtering
				skipFiltering = f.invertEventSet
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
