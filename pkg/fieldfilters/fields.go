// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package fieldfilters

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/cilium/tetragon/api/v1/tetragon"
	fieldmask_utils "github.com/mennanov/fieldmask-utils"
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

// Converts a string to camel case.
func fixupSnakeCaseString(s string, upper bool) string {
	var builder strings.Builder

	for i, r := range s {
		if s[i] == '_' {
			continue
		}
		if i == 0 && upper {
			r = unicode.ToUpper(r)
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
	builder := &strings.Builder{}
	dec := json.NewDecoder(strings.NewReader(s))
	enc := json.NewEncoder(builder)

	for {
		var dat map[string]interface{}
		err := dec.Decode(&dat)
		if err != nil {
			break
		}

		var fields string
		var ok bool

		fields, ok = dat["fields"].(string)
		if !ok {
			return s
		}

		dat["fields"] = fixupSnakeCaseString(fields, false)
		enc.Encode(&dat)
	}

	return builder.String()
}

// FieldFilter is a helper for filtering fields in events
type FieldFilter struct {
	eventSet       []tetragon.EventType
	fields         fieldmask_utils.FieldFilter
	invertEventSet bool
}

// NewFieldFilter constructs a new FieldFilter from a set of fields.
func NewFieldFilter(eventSet []tetragon.EventType, fields []string, action tetragon.FieldFilterAction, invertEventSet bool) (*FieldFilter, error) {
	var err error
	var filter fieldmask_utils.FieldFilter
	switch action {
	case tetragon.FieldFilterAction_INCLUDE:
		filter, err = fieldmask_utils.MaskFromPaths(fields, func(s string) string {
			return fixupSnakeCaseString(s, true)
		})
	case tetragon.FieldFilterAction_EXCLUDE:
		filter, err = fieldmask_utils.MaskInverseFromPaths(fields, func(s string) string {
			return fixupSnakeCaseString(s, true)
		})
	default:
		return nil, fmt.Errorf("invalid fieldfilter action: %v", action)
	}
	if err != nil {
		return nil, err
	}
	return &FieldFilter{
		eventSet:       eventSet,
		fields:         filter,
		invertEventSet: invertEventSet,
	}, nil
}

// NewIncludeFieldFilter constructs a new inclusion FieldFilter from a set of fields.
func NewIncludeFieldFilter(eventSet []tetragon.EventType, fields []string, invertEventSet bool) (*FieldFilter, error) {
	return NewFieldFilter(eventSet, fields, tetragon.FieldFilterAction_INCLUDE, invertEventSet)
}

// NewExcludeFieldFilter constructs a new exclusion FieldFilter from a set of fields.
func NewExcludeFieldFilter(eventSet []tetragon.EventType, fields []string, invertEventSet bool) (*FieldFilter, error) {
	return NewFieldFilter(eventSet, fields, tetragon.FieldFilterAction_EXCLUDE, invertEventSet)
}

// FieldFilterFromProto constructs a new FieldFilter from a Tetragon API field filter.
func FieldFilterFromProto(filter *tetragon.FieldFilter) (*FieldFilter, error) {
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
//
// nolint:revive // revive complains about stutter
func FieldFiltersFromGetEventsRequest(request *tetragon.GetEventsRequest) ([]*FieldFilter, error) {
	var filters []*FieldFilter

	for _, filter := range request.FieldFilters {
		if filter == nil {
			continue
		}

		ff, err := FieldFilterFromProto(filter)
		if err != nil {
			return nil, err
		}

		filters = append(filters, ff)
	}

	return filters, nil
}

// Filter filters the fields in the GetEventsResponse, keeping fields specified in the
// inclusion filter and discarding fields specified in the exclusion filter. Exclusion
// takes precedence over inclusion and an empty filter set will keep all remaining fields.
func (f *FieldFilter) Filter(event *tetragon.GetEventsResponse) (*tetragon.GetEventsResponse, error) {
	if len(f.eventSet) > 0 {
		// skip filtering by default unless the event set is inverted, in which case we
		// want to filter by default and skip only if we have a match
		skipFiltering := !f.invertEventSet
		eventProtoNum := tetragon.EventType_UNDEF

		rft := event.ProtoReflect()
		rft.Range(func(eventDesc protoreflect.FieldDescriptor, _ protoreflect.Value) bool {
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
			return event, nil
		}
	}

	src := event.ProtoReflect()
	dst := src.New()
	var filterErrs []error
	src.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if !src.Has(fd) {
			return true
		}

		if fd.ContainingOneof() != nil && fd.ContainingOneof().Name() == "event" {
			event := src.Get(fd).Message().Interface()
			dstEvent := dst.Mutable(fd).Message().Interface()
			err := fieldmask_utils.StructToStruct(f.fields, event, dstEvent)
			if err != nil {
				filterErrs = append(filterErrs, err)
			}
			return true
		}

		// Preserve all information that is not in the Event field
		dst.Set(fd, v)

		return true
	})

	if !src.IsValid() {
		return nil, errors.New("invalid event after field filter")
	}

	return dst.Interface().(*tetragon.GetEventsResponse), errors.Join(filterErrs...)
}
