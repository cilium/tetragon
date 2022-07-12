// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package bytesmatcher

import (
	bytes "bytes"
	json "encoding/json"
	fmt "fmt"
	strings "strings"

	yaml "sigs.k8s.io/yaml"
)

// BytesMatcher matches a []byte based on an operator and a value
type BytesMatcher struct {
	Operator Operator `json:"operator"`
	Value    []byte   `json:"value"`
}

// Operator is en enum over types of BytesMatcher
type Operator struct {
	slug string
}

// String implements fmt.Stringer
func (o Operator) String() string {
	return o.slug
}

// operatorFromString converts a string into Operator
func operatorFromString(str string) (Operator, error) {
	switch str {
	case opContains.slug:
		return opContains, nil

	case opFull.slug:
		return opFull, nil

	case opPrefix.slug:
		return opPrefix, nil

	case opSuffix.slug:
		return opSuffix, nil

	default:
		return opUnknown, fmt.Errorf("Invalid value for BytesMatcher operator: %s", str)
	}
}

// UnmarshalJSON implements json.Unmarshaler interface
func (o *Operator) UnmarshalJSON(b []byte) error {
	var str string
	err := yaml.UnmarshalStrict(b, &str)
	if err != nil {
		return err
	}

	str = strings.ToLower(str)
	operator, err := operatorFromString(str)
	if err != nil {
		return err
	}

	*o = operator
	return nil
}

// MarshalJSON implements json.Marshaler interface
func (o Operator) MarshalJSON() ([]byte, error) {
	return json.Marshal(o.slug)
}

var (
	opUnknown  = Operator{"unknown"}
	opContains = Operator{"contains"}
	opFull     = Operator{"full"}
	opPrefix   = Operator{"prefix"}
	opSuffix   = Operator{"suffix"}
)

// Match attempts to match a []byte based on the BytesMatcher
func (m *BytesMatcher) Match(value []byte) error {
	switch m.Operator {
	case opContains:
		{
			if bytes.Contains(value, m.Value) {
				return nil
			}
			return fmt.Errorf("'%v' does not contain '%v'", value, m.Value)
		}
	case opFull:
		{
			if bytes.Equal(value, m.Value) {
				return nil
			}
			return fmt.Errorf("'%v' does not match full '%v'", value, m.Value)
		}
	case opPrefix:
		{
			if bytes.HasPrefix(value, m.Value) {
				return nil
			}
			return fmt.Errorf("'%v' does not have prefix '%v'", value, m.Value)
		}
	case opSuffix:
		{
			if bytes.HasSuffix(value, m.Value) {
				return nil
			}
			return fmt.Errorf("'%v' does not have suffix '%v'", value, m.Value)
		}
	default:
		return fmt.Errorf("Unhandled BytesMatcher operator %s", m.Operator)
	}
}

// Unmarshal implements json.Unmarshaler
func (m *BytesMatcher) UnmarshalJSON(b []byte) error {
	// User just provides a plain []byte, so default to Full
	var rawVal []byte
	err := yaml.UnmarshalStrict(b, &rawVal)
	if err == nil {
		m.Operator = opFull
		m.Value = rawVal
		return nil
	}

	type Alias BytesMatcher
	var alias Alias
	err = yaml.UnmarshalStrict(b, &alias)
	if err != nil {
		return fmt.Errorf("Unmarshal BytesMatcher: %w", err)
	}
	*m = BytesMatcher(alias)
	return nil
}

// Contains constructs a new BytesMatcher that matches using the Contains operator
func Contains(value []byte) *BytesMatcher {
	return &BytesMatcher{
		Operator: opContains,
		Value:    value,
	}
}

// Full constructs a new BytesMatcher that matches using the Full operator
func Full(value []byte) *BytesMatcher {
	return &BytesMatcher{
		Operator: opFull,
		Value:    value,
	}
}

// Prefix constructs a new BytesMatcher that matches using the Prefix operator
func Prefix(value []byte) *BytesMatcher {
	return &BytesMatcher{
		Operator: opPrefix,
		Value:    value,
	}
}

// Suffix constructs a new BytesMatcher that matches using the Suffix operator
func Suffix(value []byte) *BytesMatcher {
	return &BytesMatcher{
		Operator: opSuffix,
		Value:    value,
	}
}
