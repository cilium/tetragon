// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package fieldfilters

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

const REDACTION_STR = "*****"

type RedactionFilter struct {
	binaryRegex []*regexp.Regexp
	redact      []*regexp.Regexp
}

type RedactionFilterList struct {
	list []*RedactionFilter
}

var RedactionFilters *RedactionFilterList

func ParseRedactionFilterList(filters string) (*RedactionFilterList, error) {
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
	return &RedactionFilterList{
		list: compiled,
	}, nil
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
	filter := &RedactionFilter{}

	for _, re := range protoFilter.BinaryRegex {
		compiled, err := regexp.Compile(re)
		if err != nil {
			return nil, fmt.Errorf("failed to compile binary regex `%s`: %w", re, err)
		}
		filter.binaryRegex = append(filter.binaryRegex, compiled)
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

// Redact redacts a string based on redaction filters.
func (f RedactionFilterList) Redact(binary, args string, envs []string) (string, []string) {
	for _, filter := range f.list {
		args, envs = filter.Redact(binary, args, envs)
	}
	return args, envs
}

// Redact resursively checks any string fields in the event for matches to
// redaction regexes and replaces any capture groups with `*****`.
//
// NOTE: If you're using multiple redaction filters, reach for RedactionFilterList.Redact() instead.
func (f RedactionFilter) Redact(binary, args string, envs []string) (string, []string) {
	// Default match to true if we have no binary regexes
	binaryMatch := len(f.binaryRegex) == 0
	for _, re := range f.binaryRegex {
		if re.MatchString(binary) {
			binaryMatch = true
		}
	}
	if !binaryMatch {
		return args, envs
	}

	for _, re := range f.redact {
		args, _ = redactString(re, args)
	}

	var (
		envsRedacted []string
		modified     bool
	)

	for _, v := range envs {
		for _, re := range f.redact {
			if v, modified = redactString(re, v); modified {
				break
			}
		}
		envsRedacted = append(envsRedacted, v)
	}

	return args, envsRedacted
}

func redactString(re *regexp.Regexp, s string) (string, bool) {
	modified := false
	res := re.ReplaceAllStringFunc(s, func(s string) string {
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
			modified = true
			redacted.WriteString(s[lastOffset:idx[i]])
			redacted.WriteString(REDACTION_STR)
			lastOffset = idx[i+1]
		}
		// Write the rest of the string
		redacted.WriteString(s[lastOffset:])

		return redacted.String()
	})
	return res, modified
}
