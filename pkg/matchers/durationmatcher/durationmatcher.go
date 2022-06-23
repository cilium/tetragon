// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package durationmatcher

import (
	json "encoding/json"
	fmt "fmt"
	strings "strings"
	time "time"

	durationpb "google.golang.org/protobuf/types/known/durationpb"
	yaml "sigs.k8s.io/yaml"
)

type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var str string
	err := yaml.UnmarshalStrict(b, &str)
	if err != nil {
		return err
	}

	dur, err := time.ParseDuration(str)
	if err != nil {
		return err
	}

	d.Duration = dur

	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.Duration.String())
}

type durationBetween struct {
	Lower *Duration `json:"lower"`
	Upper *Duration `json:"upper"`
}

type durationValue interface {
	// *Duration
	// *durationBetween
}

func (m *DurationMatcher) checkFull(duration *time.Duration) error {
	value, ok := m.Value.(*Duration)
	if !ok {
		return fmt.Errorf("value is not a duration")
	}

	if *duration != value.Duration {
		return fmt.Errorf("%s is not equal to expected %s", *duration, value.Duration)
	}

	return nil
}

func (m *DurationMatcher) checkLess(duration *time.Duration) error {
	value, ok := m.Value.(*Duration)
	if !ok {
		return fmt.Errorf("value is not a duration")
	}

	if !(*duration <= value.Duration) {
		return fmt.Errorf("%s is not less than %s", *duration, value.Duration)
	}

	return nil
}

func (m *DurationMatcher) checkGreater(duration *time.Duration) error {
	value, ok := m.Value.(*Duration)
	if !ok {
		return fmt.Errorf("value is not a duration")
	}

	if !(*duration >= value.Duration) {
		return fmt.Errorf("%s is not greater than than %s", *duration, value.Duration)
	}

	return nil
}

func (m *DurationMatcher) checkBetween(duration *time.Duration) error {
	value, ok := m.Value.(*durationBetween)
	if !ok {
		return fmt.Errorf("value is not a duration")
	}

	if value.Upper == nil || value.Lower == nil {
		return fmt.Errorf("value is nil")
	}

	if !(*duration <= value.Upper.Duration) {
		return fmt.Errorf("%s is not less than %s", *duration, value.Upper.Duration)
	}

	if !(*duration >= value.Lower.Duration) {
		return fmt.Errorf("%s is not greater than %s", *duration, value.Lower.Duration)
	}

	return nil
}

// DurationMatcher matches a *durationpb.Duration based on an operator and a value
type DurationMatcher struct {
	Operator Operator      `json:"operator"`
	Value    durationValue `json:"value"`
}

// Operator is en enum over types of DurationMatcher
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
	case opBetween.slug:
		return opBetween, nil

	case opFull.slug:
		return opFull, nil

	case opGreater.slug:
		return opGreater, nil

	case opLess.slug:
		return opLess, nil

	default:
		return opUnknown, fmt.Errorf("Invalid value for DurationMatcher operator: %s", str)
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
	opUnknown = Operator{"unknown"}
	opBetween = Operator{"between"}
	opFull    = Operator{"full"}
	opGreater = Operator{"greater"}
	opLess    = Operator{"less"}
)

// Match attempts to match a *durationpb.Duration based on the DurationMatcher
func (m *DurationMatcher) Match(value *durationpb.Duration) error {
	switch m.Operator {
	case opBetween:
		{
			if m.Value == nil {
				return fmt.Errorf("matcher value is nil")
			}
			if value == nil {
				return fmt.Errorf("duration is nil")
			}
			dur := value.AsDuration()
			return m.checkBetween(&dur)
		}
	case opFull:
		{
			if m.Value == nil {
				return fmt.Errorf("matcher value is nil")
			}
			if value == nil {
				return fmt.Errorf("duration is nil")
			}
			dur := value.AsDuration()
			return m.checkFull(&dur)
		}
	case opGreater:
		{
			if m.Value == nil {
				return fmt.Errorf("matcher value is nil")
			}
			if value == nil {
				return fmt.Errorf("duration is nil")
			}
			dur := value.AsDuration()
			return m.checkGreater(&dur)
		}
	case opLess:
		{
			if m.Value == nil {
				return fmt.Errorf("matcher value is nil")
			}
			if value == nil {
				return fmt.Errorf("duration is nil")
			}
			dur := value.AsDuration()
			return m.checkLess(&dur)
		}
	default:
		return fmt.Errorf("Unhandled DurationMatcher operator %s", m.Operator)
	}
}

// Marshal implements json.Marshaler
func (m DurationMatcher) MarshalJSON() ([]byte, error) {
	type Alias DurationMatcher
	switch valueType := m.Value.(type) {
	case *Duration:
		return json.Marshal(&struct {
			Value *Duration `json:"value"`
			*Alias
		}{
			Value: valueType,
			Alias: (*Alias)(&m),
		})
	case *durationBetween:
		return json.Marshal(&struct {
			Value *durationBetween `json:"value"`
			*Alias
		}{
			Value: valueType,
			Alias: (*Alias)(&m),
		})
	default:
		return nil, fmt.Errorf("Marshal DurationMatcher: Invalid match value")
	}
}

// Unmarshal implements json.Unmarshaler
func (m *DurationMatcher) UnmarshalJSON(b []byte) error {
	// User just provides a plain durationValue, so default to Full
	var rawVal Duration
	err := yaml.UnmarshalStrict(b, &rawVal)
	if err == nil {
		m.Operator = opFull
		m.Value = (durationValue)(&rawVal)
		return nil
	}

	type Alias DurationMatcher
	{
		temp := struct {
			Value *Duration `json:"value"`
			*Alias
		}{Alias: (*Alias)(m)}
		if err := yaml.UnmarshalStrict(b, &temp); err == nil {
			m.Value = temp.Value
			return nil
		}
	}
	{
		temp := struct {
			Value *durationBetween `json:"value"`
			*Alias
		}{Alias: (*Alias)(m)}
		if err := yaml.UnmarshalStrict(b, &temp); err == nil {
			m.Value = temp.Value
			return nil
		}
	}
	return fmt.Errorf("Unmarshal DurationMatcher: Failed to unmarshal")
}

// Between constructs a new DurationMatcher that matches using the Between operator
func Between(lower *Duration, upper *Duration) *DurationMatcher {
	return &DurationMatcher{
		Operator: opBetween,
		Value: &durationBetween{
			Lower: lower,
			Upper: upper,
		},
	}
}

// Full constructs a new DurationMatcher that matches using the Full operator
func Full(value *Duration) *DurationMatcher {
	return &DurationMatcher{
		Operator: opFull,
		Value:    value,
	}
}

// Greater constructs a new DurationMatcher that matches using the Greater operator
func Greater(value *Duration) *DurationMatcher {
	return &DurationMatcher{
		Operator: opGreater,
		Value:    value,
	}
}

// Less constructs a new DurationMatcher that matches using the Less operator
func Less(value *Duration) *DurationMatcher {
	return &DurationMatcher{
		Operator: opLess,
		Value:    value,
	}
}
