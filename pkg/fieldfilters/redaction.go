// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package fieldfilters

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/filters"
	v1 "github.com/cilium/tetragon/pkg/oldhubble/api/v1"
	hubbleFilters "github.com/cilium/tetragon/pkg/oldhubble/filters"
	"google.golang.org/protobuf/reflect/protopath"
	"google.golang.org/protobuf/reflect/protorange"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const REDACTION_STR = "*****"

type RedactionFilter struct {
	match  hubbleFilters.FilterFuncs
	redact []*regexp.Regexp
}

type RedactionFilterList []*RedactionFilter

func ParseRedactionFilterList(filters string) (RedactionFilterList, error) {
	if filters == "" {
		return nil, nil
	}
	dec := json.NewDecoder(strings.NewReader(filters))
	var results []*tetragon.RedactionFilter
	for {
		var result tetragon.RedactionFilter
		if err := dec.Decode(&result); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("failed to parse redaction filter list: %w", err)
		}
		results = append(results, &result)
	}
	compiled, err := RedactionFilterListFromProto(results)
	if err != nil {
		return nil, err
	}
	return compiled, nil
}

func RedactionFilterListFromProto(protoFilters []*tetragon.RedactionFilter) ([]*RedactionFilter, error) {
	var filters []*RedactionFilter
	for _, f := range protoFilters {
		filter, err := redactionFilterFromProto(f)
		if err != nil {
			return nil, err
		}
		filters = append(filters, filter)
	}

	return filters, nil
}

// redactionFilterFromProto constructs a new RedactionFilter from a Tetragon API redaction filter.
func redactionFilterFromProto(protoFilter *tetragon.RedactionFilter) (*RedactionFilter, error) {
	var err error
	filter := &RedactionFilter{}

	// Construct match funcs
	filter.match, err = filters.BuildFilterList(context.TODO(), protoFilter.Match, filters.Filters)
	if err != nil {
		return nil, fmt.Errorf("failed to construct match for redaction filter: %w", err)
	}

	if len(protoFilter.Redact) == 0 {
		return nil, fmt.Errorf("refusing to construct redaction filter with no redactions")
	}

	// Compile regex
	for _, re := range protoFilter.Redact {
		compiled, err := regexp.Compile(re)
		if err != nil {
			return nil, fmt.Errorf("failed to compile redaction regex `%s`: %w", re, err)
		}
		filter.redact = append(filter.redact, compiled)
	}

	return filter, nil
}

// Redact resursively checks any string fields in the event for matches to
// redaction regexes and replaces any capture groups with `*****`.
func (f RedactionFilterList) Redact(event *tetragon.GetEventsResponse) {
	// We need to do this in two batch stages: match and redact.
	// This is necessary to handle the case where we have a redaction filter
	// earlier in the list that would redact a field used in a match statement
	// of another redaction filter later in the list. If we don't do the
	// matching first, the second redaction filter would never match.
	doesMatch := []bool{}
	ev := &v1.Event{Event: event}
	for _, filter := range f {
		doesMatch = append(doesMatch, filter.match.MatchOne(ev))
	}

	for i := range f {
		if !doesMatch[i] {
			continue
		}
		f[i].doRedact(event.ProtoReflect())
	}
}

// Redact resursively checks any string fields in the event for matches to
// redaction regexes and replaces any capture groups with `*****`.
//
// NOTE: If you're using multiple redaction filters, reach for RedactionFilterList.Redact() instead.
func (f RedactionFilter) Redact(event *tetragon.GetEventsResponse) {
	ev := &v1.Event{Event: event}
	if !f.match.MatchOne(ev) {
		return
	}
	f.doRedact(event.ProtoReflect())
}

func (f *RedactionFilter) doRedact(msg protoreflect.Message) {
	protorange.Range(msg, func(p protopath.Values) error {
		last := p.Index(-1)
		s, ok := last.Value.Interface().(string)
		if !ok {
			return nil
		}

		for _, re := range f.redact {
			s = redactString(re, s)
		}

		beforeLast := p.Index(-2)
		switch last.Step.Kind() {
		case protopath.FieldAccessStep:
			m := beforeLast.Value.Message()
			fd := last.Step.FieldDescriptor()
			m.Set(fd, protoreflect.ValueOfString(s))
		case protopath.ListIndexStep:
			ls := beforeLast.Value.List()
			i := last.Step.ListIndex()
			ls.Set(i, protoreflect.ValueOfString(s))
		case protopath.MapIndexStep:
			ms := beforeLast.Value.Map()
			k := last.Step.MapIndex()
			ms.Set(k, protoreflect.ValueOfString(s))
		}

		return nil
	})
}

func redactString(re *regexp.Regexp, s string) string {
	s = re.ReplaceAllStringFunc(s, func(s string) string {
		var redacted strings.Builder

		idx := re.FindStringSubmatchIndex(s)
		if len(idx) < 2 {
			return s
		}

		// Skip first idx pair which is entire string
		lastOffset := 0
		for i := 2; i < len(idx); i += 2 {
			// Handle nested capture groups that have already been redacted
			if idx[i] < lastOffset {
				continue
			}
			redacted.WriteString(s[lastOffset:idx[i]])
			redacted.WriteString(REDACTION_STR)
			lastOffset = idx[i+1]
		}
		// Write the rest of the string
		redacted.WriteString(s[lastOffset:])

		return redacted.String()
	})
	return s
}
