// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// serializer.go provides JSON serialization and deserialization with type preservation
// for interface fields. This enables roundtrip of events through JSON while maintaining
// concrete type information.

package synthetic

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// Serializer implements Codec with type-preserving serialization.
type Serializer struct{}

// Marshal serializes any value with type wrapper at top level and for interface fields.
func (Serializer) Marshal(v any) ([]byte, error) {
	ifaceVal := reflect.ValueOf(&v).Elem()
	wrapped, err := wrapValue(ifaceVal)
	if err != nil {
		return nil, err
	}
	return json.Marshal(wrapped)
}

// Unmarshal deserializes JSON with type wrappers.
func (Serializer) Unmarshal(data []byte) (any, error) {
	var wrapper TypedValue
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return nil, fmt.Errorf("failed to unmarshal event wrapper: %w", err)
	}

	if wrapper.Type == "" {
		return nil, errors.New("missing type in event wrapper")
	}

	factory, ok := InterfaceRegistry[wrapper.Type]
	if !ok {
		return nil, fmt.Errorf("unknown type: %s", wrapper.Type)
	}

	event := factory()
	if err := unmarshalWithTypes(wrapper.Value, event); err != nil {
		return nil, err
	}
	return event, nil
}

// unmarshalWithTypes deserializes JSON with type wrappers back to the target.
func unmarshalWithTypes(data []byte, v any) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Ptr || rv.IsNil() {
		return errors.New("target must be non-nil pointer")
	}

	// Use Decoder with UseNumber to preserve precision for large integers (uint64)
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	var raw any
	if err := dec.Decode(&raw); err != nil {
		return err
	}

	return unwrapInto(raw, rv.Elem())
}

// getTypeName returns the type name for a value (e.g. "*tracing.MsgGenericKprobeUnix").
func getTypeName(v any) string {
	return reflect.TypeOf(v).String()
}

// wrapValue recursively wraps interface values with type info.
func wrapValue(v reflect.Value) (any, error) {
	switch v.Kind() {
	case reflect.Interface:
		if v.IsNil() {
			return nil, nil
		}
		elem := v.Elem()
		// Wrap interface value with type info
		wrapped, err := wrapValue(elem)
		if err != nil {
			return nil, err
		}
		data, err := json.Marshal(wrapped)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal interface value: %w", err)
		}
		return TypedValue{
			Type:  getTypeName(elem.Interface()),
			Value: data,
		}, nil

	case reflect.Ptr:
		if v.IsNil() {
			return nil, nil
		}
		// For pointers, wrap the element and return as-is (json.Marshal handles pointers)
		return wrapValue(v.Elem())

	case reflect.Struct:
		result := make(map[string]any)
		t := v.Type()
		for i := range v.NumField() {
			field := t.Field(i)
			if !field.IsExported() {
				continue
			}
			name := getJSONFieldName(field)
			if name == "-" {
				continue
			}
			wrapped, err := wrapValue(v.Field(i))
			if err != nil {
				return nil, fmt.Errorf("field %s: %w", name, err)
			}
			result[name] = wrapped
		}
		return result, nil

	case reflect.Slice:
		if v.IsNil() {
			return nil, nil
		}
		result := make([]any, v.Len())
		for i := range v.Len() {
			wrapped, err := wrapValue(v.Index(i))
			if err != nil {
				return nil, fmt.Errorf("index %d: %w", i, err)
			}
			result[i] = wrapped
		}
		return result, nil

	case reflect.Map:
		if v.IsNil() {
			return nil, nil
		}
		result := make(map[string]any)
		for _, key := range v.MapKeys() {
			wrapped, err := wrapValue(v.MapIndex(key))
			if err != nil {
				return nil, fmt.Errorf("map key %v: %w", key.Interface(), err)
			}
			result[fmt.Sprint(key.Interface())] = wrapped
		}
		return result, nil

	case reflect.Array:
		result := make([]any, v.Len())
		for i := range v.Len() {
			wrapped, err := wrapValue(v.Index(i))
			if err != nil {
				return nil, fmt.Errorf("index %d: %w", i, err)
			}
			result[i] = wrapped
		}
		return result, nil

	default:
		return v.Interface(), nil
	}
}

// unwrapInto recursively unwraps typed values into the target.
func unwrapInto(raw any, target reflect.Value) error {
	if raw == nil {
		return nil
	}

	// Check if this is a typed wrapper
	if m, ok := raw.(map[string]any); ok {
		if typeName, hasType := m["synthetic_type"]; hasType {
			if valueRaw, hasValue := m["synthetic_value"]; hasValue {
				typeNameStr, ok := typeName.(string)
				if !ok {
					return fmt.Errorf("synthetic_type must be string, got %T", typeName)
				}
				return unwrapTypedValue(typeNameStr, valueRaw, target)
			}
		}
	}

	switch target.Kind() {
	case reflect.Interface:
		// Should not happen if serialization is correct - all interfaces should have typed wrappers
		return fmt.Errorf("interface field without typed wrapper, got %T", raw)

	case reflect.Ptr:
		if target.IsNil() {
			target.Set(reflect.New(target.Type().Elem()))
		}
		return unwrapInto(raw, target.Elem())

	case reflect.Struct:
		m, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("expected map for struct, got %T", raw)
		}

		t := target.Type()
		for i := range target.NumField() {
			field := t.Field(i)
			if !field.IsExported() {
				continue
			}
			name := getJSONFieldName(field)
			if val, exists := m[name]; exists {
				if err := unwrapInto(val, target.Field(i)); err != nil {
					return fmt.Errorf("field %s: %w", name, err)
				}
			}
		}
		return nil

	case reflect.Slice:
		arr, ok := raw.([]any)
		if !ok {
			return fmt.Errorf("expected array for slice, got %T", raw)
		}

		slice := reflect.MakeSlice(target.Type(), len(arr), len(arr))
		for i, elem := range arr {
			if err := unwrapInto(elem, slice.Index(i)); err != nil {
				return fmt.Errorf("index %d: %w", i, err)
			}
		}
		target.Set(slice)
		return nil

	case reflect.Array:
		arr, ok := raw.([]any)
		if !ok {
			return fmt.Errorf("expected array for array, got %T", raw)
		}

		for i := 0; i < target.Len() && i < len(arr); i++ {
			if err := unwrapInto(arr[i], target.Index(i)); err != nil {
				return fmt.Errorf("index %d: %w", i, err)
			}
		}
		return nil

	case reflect.Map:
		m, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("expected map for map, got %T", raw)
		}

		if target.IsNil() {
			target.Set(reflect.MakeMap(target.Type()))
		}
		for k, v := range m {
			keyVal := reflect.New(target.Type().Key()).Elem()
			if err := setBasicValue(keyVal, k); err != nil {
				return fmt.Errorf("map key %q: %w", k, err)
			}
			valVal := reflect.New(target.Type().Elem()).Elem()
			if err := unwrapInto(v, valVal); err != nil {
				return err
			}
			target.SetMapIndex(keyVal, valVal)
		}
		return nil

	default:
		return setBasicValue(target, raw)
	}
}

// unwrapTypedValue creates an instance from registry and unmarshals the value.
func unwrapTypedValue(typeName string, valueRaw any, target reflect.Value) error {
	factory, ok := InterfaceRegistry[typeName]
	if !ok {
		return fmt.Errorf("unknown type in registry: %s", typeName)
	}

	instance := factory()
	instanceVal := reflect.ValueOf(instance)

	if err := unwrapInto(valueRaw, instanceVal.Elem()); err != nil {
		return err
	}

	// Set based on whether original was pointer or value
	if strings.HasPrefix(typeName, "*") {
		target.Set(instanceVal)
	} else {
		target.Set(instanceVal.Elem())
	}

	return nil
}

// getJSONFieldName returns the JSON field name for a struct field.
func getJSONFieldName(field reflect.StructField) string {
	tag := field.Tag.Get("json")
	if tag == "" {
		return field.Name
	}
	parts := strings.Split(tag, ",")
	if parts[0] == "" {
		return field.Name
	}
	return parts[0]
}

// setBasicValue sets a basic value from raw JSON data.
func setBasicValue(target reflect.Value, raw any) error {
	targetKind := target.Kind()

	// Get string representation for parsing
	var s string
	switch v := raw.(type) {
	case json.Number:
		s = v.String()
	case string:
		s = v
	case bool:
		if targetKind == reflect.Bool {
			target.SetBool(v)
			return nil
		}
		return fmt.Errorf("cannot assign bool to %v", targetKind)
	}

	// Parse string into target type
	switch targetKind {
	case reflect.String:
		target.SetString(s)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid int %q: %w", s, err)
		}
		target.SetInt(n)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid uint %q: %w", s, err)
		}
		target.SetUint(n)
	case reflect.Float32, reflect.Float64:
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return fmt.Errorf("invalid float %q: %w", s, err)
		}
		target.SetFloat(f)
	default:
		return fmt.Errorf("cannot assign %q to %v", s, targetKind)
	}
	return nil
}
