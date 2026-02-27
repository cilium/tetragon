// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Package synthetic provides components for recording and replaying Tetragon events.
// This includes:
// - EventListener: writes events to a file for later replay
// - FileObserver: reads and replays events from a file
package synthetic

import (
	"encoding/json"
	"reflect"
)

// Codec provides type-preserving serialization for events.
type Codec interface {
	Marshal(v any) ([]byte, error)
	Unmarshal(data []byte) (any, error)
}

// TypedValue wraps any interface value with type info for JSON serialization.
type TypedValue struct {
	Type  string          `json:"synthetic_type"`
	Value json.RawMessage `json:"synthetic_value"`
}

// InterfaceRegistry maps type names to factory functions for creating interface instances.
// Used during unmarshal to reconstruct typed values from JSON.
var InterfaceRegistry = make(map[string]func() any)

// RegisterType adds a type to the interface registry.
// Call with a typed nil pointer: RegisterType((*MyType)(nil))
// Registers both pointer and non-pointer names to handle both cases during unmarshal.
func RegisterType(v any) {
	t := reflect.TypeOf(v)
	ptrName := t.String() // e.g. "*tracing.MsgGenericKprobeUnix"

	// Unwrap all pointer levels (handles **T, ***T, etc.)
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	valueName := t.String() // e.g. "tracing.MsgGenericKprobeUnix"

	factory := func() any {
		return reflect.New(t).Interface()
	}

	// Register both pointer and value type names
	InterfaceRegistry[ptrName] = factory
	InterfaceRegistry[valueName] = factory
}
