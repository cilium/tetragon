// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package option

import (
	"maps"
	"slices"
	"strings"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

var AncestorsEventTypeMap = map[tetragon.EventType]string{
	tetragon.EventType_PROCESS_EXEC:       "base",
	tetragon.EventType_PROCESS_EXIT:       "base",
	tetragon.EventType_PROCESS_KPROBE:     "kprobe",
	tetragon.EventType_PROCESS_TRACEPOINT: "tracepoint",
	tetragon.EventType_PROCESS_UPROBE:     "uprobe",
	tetragon.EventType_PROCESS_LSM:        "lsm",
}

func GetAncestorsEventTypes() []tetragon.EventType {
	return slices.Collect(maps.Keys(AncestorsEventTypeMap))
}

type AncestorsEventFilter map[string]bool

func DefaultEnableAncestors() AncestorsEventFilter {
	return AncestorsEventFilter{
		"base":       false,
		"kprobe":     false,
		"tracepoint": false,
		"uprobe":     false,
		"lsm":        false,
	}
}

func ParseEnableAncestors(eventTypesString string) []string {
	eventTypes := []string{}
	for _, t := range strings.Split(eventTypesString, ",") {
		t = strings.TrimSpace(t)
		eventTypes = append(eventTypes, t)
	}
	return eventTypes
}

// WithEnabledAncestors returns a new AncestorsEventFilter with only the event types in eventTypes enabled.
// If eventTypes is nil, a copy of the original AncestorsEventFilter is returned.
// If eventTypes is empty, all event types are disabled.
// If eventTypes contains event types that are not in the original AncestorsEventFilter, they are ignored.
func (f AncestorsEventFilter) WithEnabledAncestors(eventTypes []string) AncestorsEventFilter {
	ancestorsEventFilter := maps.Clone(f)
	if eventTypes == nil {
		return ancestorsEventFilter
	}

	// disable all configurable event types
	for t := range f {
		ancestorsEventFilter[t] = false
	}

	if slices.Contains(eventTypes, "base") {
		// enable configured event types
		for _, t := range eventTypes {
			// quietly ignore unknown event types
			if _, ok := ancestorsEventFilter[t]; ok {
				ancestorsEventFilter[t] = true
			}
		}
	}

	return ancestorsEventFilter
}
