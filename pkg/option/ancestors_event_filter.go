// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package option

import "github.com/cilium/tetragon/api/v1/tetragon"

// All process event types that currently support ancestors.
var AncestorsEventTypes = []tetragon.EventType{
	tetragon.EventType_PROCESS_EXEC,
	tetragon.EventType_PROCESS_EXIT,
	tetragon.EventType_PROCESS_KPROBE,
	tetragon.EventType_PROCESS_TRACEPOINT,
	tetragon.EventType_PROCESS_UPROBE,
	tetragon.EventType_PROCESS_LSM,
}

// AncestorsEnabled returns the value of the configuration option responsible for
// enabling process ancestors for events with the specified eventType.
// If events with the specified eventType don't support ancestors, false is returned.
func AncestorsEnabled(eventType tetragon.EventType) bool {
	switch eventType {
	case tetragon.EventType_PROCESS_EXEC, tetragon.EventType_PROCESS_EXIT:
		return Config.EnableProcessAncestors
	case tetragon.EventType_PROCESS_KPROBE:
		return Config.EnableProcessKprobeAncestors
	case tetragon.EventType_PROCESS_TRACEPOINT:
		return Config.EnableProcessTracepointAncestors
	case tetragon.EventType_PROCESS_UPROBE:
		return Config.EnableProcessUprobeAncestors
	case tetragon.EventType_PROCESS_LSM:
		return Config.EnableProcessLsmAncestors
	default:
		return false
	}
}
