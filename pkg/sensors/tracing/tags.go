// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"errors"
	"fmt"
	"strconv"
)

const (
	// Max tags of a Tracing Policy
	TpMaxTags   = 16
	TpMinTagLen = 2
	TpMaxTagLen = 128
)

var (
	ErrTagsSyntaxLong = errors.New("tags field: too many tags")
	ErrTagSyntaxShort = errors.New("too short")
)

func escapeTag(tag string) (string, error) {
	if len(tag) < TpMinTagLen {
		return "", ErrTagSyntaxShort
	} else if len(tag) > TpMaxTagLen {
		tag = tag[:TpMaxTagLen]
	}

	escapedTag := strconv.Quote(tag)
	// Remove double quoted string so we pretty print it later in the events
	return escapedTag[1 : len(escapedTag)-1], nil
}

// getPolicyTags() Validates and escapes the passed tags.
// Returns: On success the validated tags of max length TpMaxTags
// On failures an error is set.
func getPolicyTags(tags []string) ([]string, error) {
	if len(tags) == 0 {
		return nil, nil
	} else if len(tags) > TpMaxTags {
		return nil, ErrTagsSyntaxLong
	}

	var newTags []string
	for i, v := range tags {
		parsed, err := escapeTag(v)
		if err != nil {
			return nil, fmt.Errorf("custom tag n%d: %w", i, err)
		}
		newTags = append(newTags, parsed)
	}

	return newTags, nil
}
