// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Package synthetic provides components for recording and replaying Tetragon events.
// This includes:
// - EventListener: writes events to a file for later replay
// - Reader: reads and replays events from a file
package synthetic

import (
	"encoding/json"

	"github.com/cilium/tetragon/pkg/api/readyapi"
	"github.com/cilium/tetragon/pkg/grpc/exec"
	"github.com/cilium/tetragon/pkg/reader/notify"
)

// Event represents a logged event with type name and JSON payload.
// This format is used for serializing events to JSON lines files.
type Event struct {
	Type  string          `json:"type"`  // Go type name from reflect.TypeOf().String()
	Event json.RawMessage `json:"event"` // JSON-serialized event
}

// TypeRegistry maps type names to factory functions for creating event instances.
// Used during replay to reconstruct typed events from JSON.
var TypeRegistry = map[string]func() notify.Message{
	"*exec.MsgExecveEventUnix": func() notify.Message { return &exec.MsgExecveEventUnix{} },
	"*exec.MsgExitEventUnix":   func() notify.Message { return &exec.MsgExitEventUnix{} },
	"*exec.MsgCloneEventUnix":  func() notify.Message { return &exec.MsgCloneEventUnix{} },
	"*exec.MsgCgroupEventUnix": func() notify.Message { return &exec.MsgCgroupEventUnix{} },
	"*exec.MsgKThreadInitUnix": func() notify.Message { return &exec.MsgKThreadInitUnix{} },
	"*readyapi.MsgTetragonReady": func() notify.Message { return &readyapi.MsgTetragonReady{} },
}
