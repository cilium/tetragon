// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package mapmatcher

import (
	"fmt"

	"sigs.k8s.io/yaml"
)

// Matcher is a generic interface for matching values of type T.
type Matcher[T any] interface {
	Match(T) error
}

// MapMatcher matches a map of type map[K]V using matchers for each value.
// K is the key type, V is the value type, and M is the matcher type for V.
type MapMatcher[K comparable, V any, M any] map[K]M

// Match matches the actual map against the expected matchers.
// It iterates over all expected matchers and ensures they match the values in the actual map.
func (m MapMatcher[K, V, M]) Match(actual map[K]V) error {
	var unmatched []K

	for key, matcher := range m {
		val, ok := actual[key]
		if !ok {
			unmatched = append(unmatched, key)
			continue
		}

		// Try to match using the value or its pointer. This allows MapMatcher to work
		// with matchers that have pointer receivers even when stored as values in the map.
		var err error
		if im, ok := any(matcher).(interface{ Match(V) error }); ok {
			err = im.Match(val)
		} else if im, ok := any(&matcher).(interface{ Match(V) error }); ok {
			err = im.Match(val)
		} else {
			return fmt.Errorf("key %v: matcher of type %T does not implement Match(%T) error", key, matcher, val)
		}

		if err != nil {
			return fmt.Errorf("key %v match failed: %w", key, err)
		}
	}

	if len(unmatched) > 0 {
		return fmt.Errorf("unmatched keys: %v", unmatched)
	}

	return nil
}

// UnmarshalJSON implements json.Unmarshaler for MapMatcher.
func (m *MapMatcher[K, V, M]) UnmarshalJSON(b []byte) error {
	type Alias MapMatcher[K, V, M]
	var alias Alias
	if err := yaml.UnmarshalStrict(b, &alias); err != nil {
		return fmt.Errorf("unmarshal MapMatcher: %w", err)
	}
	*m = MapMatcher[K, V, M](alias)
	return nil
}

// PrimitiveMatcher is a generic matcher for primitive types (string, int, bool, etc.)
// that performs a simple equality check.
type PrimitiveMatcher[V comparable] struct {
	Value V `json:"value"`
}

// Match implements the Matcher interface for PrimitiveMatcher.
func (m PrimitiveMatcher[V]) Match(actual V) error {
	if m.Value != actual {
		return fmt.Errorf("expected %v, got %v", m.Value, actual)
	}
	return nil
}

// UnmarshalJSON implements json.Unmarshaler for PrimitiveMatcher.
// It allows the user to provide a plain value as a shorthand for the matcher.
func (m *PrimitiveMatcher[V]) UnmarshalJSON(b []byte) error {
	// Try to unmarshal as a plain value first
	var val V
	if err := yaml.UnmarshalStrict(b, &val); err == nil {
		m.Value = val
		return nil
	}

	// Otherwise, unmarshal as a struct
	type Alias PrimitiveMatcher[V]
	var alias Alias
	if err := yaml.UnmarshalStrict(b, &alias); err != nil {
		return fmt.Errorf("unmarshal PrimitiveMatcher: %w", err)
	}
	*m = PrimitiveMatcher[V](alias)
	return nil
}

// Operator strings for PrimitiveMatcher
func (m PrimitiveMatcher[V]) Operator() string {
	return "Equals"
}

// String returns a string representation of the matcher.
func (m PrimitiveMatcher[V]) String() string {
	return fmt.Sprintf("%v", m.Value)
}
