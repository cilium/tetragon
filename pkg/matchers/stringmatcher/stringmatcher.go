// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package stringmatcher

import (
	json "encoding/json"
	fmt "fmt"
	regexp "regexp"
	strings "strings"

	yaml "sigs.k8s.io/yaml"
)

// Operator is en enum over types of StringMatcher
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

	case opRegex.slug:
		return opRegex, nil

	case opSuffix.slug:
		return opSuffix, nil

	default:
		return opUnknown, fmt.Errorf("Invalid value for StringMatcher operator: %s", str)
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
	opRegex    = Operator{"regex"}
	opSuffix   = Operator{"suffix"}
)

// Match attempts to match a string based on the StringMatcher
func (m *StringMatcher) Match(value string) error {
	switch m.Operator {
	case opContains:
		{
			if strings.Contains(value, m.Value) {
				return nil
			}
			return fmt.Errorf("'%s' does not contain '%s'", value, m.Value)
		}
	case opFull:
		{
			if value == m.Value {
				return nil
			}
			return fmt.Errorf("'%s' does not match full '%s'", value, m.Value)
		}
	case opPrefix:
		{
			if strings.HasPrefix(value, m.Value) {
				return nil
			}
			return fmt.Errorf("'%s' does not have prefix '%s'", value, m.Value)
		}
	case opRegex:
		{ // Compile the regex if it hasn't already been compiled
			if m.regex == nil {
				var err error
				m.regex, err = regexp.Compile(m.Value)
				if err != nil {
					return fmt.Errorf("Invalid regex '%s': %v", m.Value, err)
				}
			}

			// Check whether the regex matches
			if m.regex.Match([]byte(value)) {
				return nil
			}

			return fmt.Errorf("'%s' does not match regex '%s'", value, m.Value)
		}
	case opSuffix:
		{
			if strings.HasSuffix(value, m.Value) {
				return nil
			}
			return fmt.Errorf("'%s' does not have suffix '%s'", value, m.Value)
		}
	default:
		return fmt.Errorf("Unhandled StringMatcher operator %s", m.Operator)
	}
}

// Contains constructs a new StringMatcher that matches using the Contains operator
func Contains(value string) *StringMatcher {
	return &StringMatcher{
		Operator: opContains,
		Value:    value,
	}
}

// Full constructs a new StringMatcher that matches using the Full operator
func Full(value string) *StringMatcher {
	return &StringMatcher{
		Operator: opFull,
		Value:    value,
	}
}

// Prefix constructs a new StringMatcher that matches using the Prefix operator
func Prefix(value string) *StringMatcher {
	return &StringMatcher{
		Operator: opPrefix,
		Value:    value,
	}
}

// Regex constructs a new StringMatcher that matches using the Regex operator
func Regex(value string) *StringMatcher {
	return &StringMatcher{
		Operator: opRegex,
		Value:    value,
	}
}

// Suffix constructs a new StringMatcher that matches using the Suffix operator
func Suffix(value string) *StringMatcher {
	return &StringMatcher{
		Operator: opSuffix,
		Value:    value,
	}
}

// StringMatcher matches a string based on an operator and a value
type StringMatcher struct {
	Operator Operator       `json:"operator"`
	Value    string         `json:"value"`
	regex    *regexp.Regexp `json:"-"`
}

// Unmarshal implements json.Unmarshaler
func (m *StringMatcher) UnmarshalJSON(b []byte) error {
	// User just provides a plain string, so default to Full
	var rawVal string
	err := yaml.UnmarshalStrict(b, &rawVal)
	if err == nil {
		m.Operator = opFull
		m.Value = rawVal
		return nil
	}

	type Alias StringMatcher
	var alias Alias
	err = yaml.UnmarshalStrict(b, &alias)
	if err != nil {
		return fmt.Errorf("Unmarshal StringMatcher: %w", err)
	}
	*m = StringMatcher(alias)

	// Compile the regex ahead of time to we can return an unmarshal error if it fails
	// and we won't have to do it on every match
	if m.Operator == opRegex {
		re, err := regexp.Compile(m.Value)
		if err != nil {
			return fmt.Errorf("Unmarshal StringMatcher: Invalid regex '%s': %v", m.Value, err)
		}
		m.regex = re
	}

	return nil
}
