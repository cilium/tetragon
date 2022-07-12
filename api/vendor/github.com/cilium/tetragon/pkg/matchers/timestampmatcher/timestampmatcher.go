// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package timestampmatcher

import (
	json "encoding/json"
	fmt "fmt"
	strings "strings"
	time "time"

	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	yaml "sigs.k8s.io/yaml"
)

var formats = []string{
	time.RFC3339,
	"2006-01-02T15:04:05.999999999Z",
	"2006-01-02T15:04:05.999999999",
	"2006-01-02T15:04:05Z",
	"2006-01-02T15:04:05",
}

type Time struct {
	time.Time
}

func (t *Time) UnmarshalJSON(b []byte) error {
	var s string
	err := yaml.UnmarshalStrict(b, &s)
	if err != nil {
		return err
	}

	for _, format := range formats {
		t_, err := time.Parse(format, s)
		if err == nil {
			t.Time = t_.UTC()
			return nil
		}
	}

	return fmt.Errorf("Unmarshal Time: Failed to parse time %s as RFC3339", s)
}

type timestampBetween struct {
	After  *Time `json:"after"`
	Before *Time `json:"before"`
}

type timestampFormat struct {
	Format    string `json:"format"`
	Timestamp *Time  `json:"time"`
}

type timestampValue interface {
	// *Time
	// *timestampBetween
	// *timestampFormat
}

func (m *TimestampMatcher) checkDay(ts *time.Time) error {
	value, ok := m.Value.(*Time)
	if !ok {
		return fmt.Errorf("value is not a timestamp")
	}

	tsYear := ts.Year()
	tcYear := value.Year()

	if tsYear != tcYear {
		return fmt.Errorf("year %04d does not match expected %04d", tsYear, tcYear)
	}

	tsMonth := ts.Month()
	tcMonth := value.Month()

	if tsMonth != tcMonth {
		return fmt.Errorf("month %02d does not match expected %02d", tsMonth, tcMonth)
	}

	tsDay := ts.Day()
	tcDay := value.Day()

	if tsDay != tcDay {
		return fmt.Errorf("day %02d does not match expected %02d", tsDay, tcDay)
	}

	return nil
}

func (m *TimestampMatcher) checkHour(ts *time.Time) error {
	value, ok := m.Value.(*Time)
	if !ok {
		return fmt.Errorf("value is not a timestamp")
	}

	if err := m.checkDay(ts); err != nil {
		return err
	}

	tsHour := ts.Hour()
	tcHour := value.Hour()

	if tsHour != tcHour {
		return fmt.Errorf("hour %02d does not match expected %02d", tsHour, tcHour)
	}

	return nil
}

func (m *TimestampMatcher) checkMinute(ts *time.Time) error {
	value, ok := m.Value.(*Time)
	if !ok {
		return fmt.Errorf("value is not a timestamp")
	}

	if err := m.checkHour(ts); err != nil {
		return err
	}

	tsMinute := ts.Minute()
	tcMinute := value.Minute()

	if tsMinute != tcMinute {
		return fmt.Errorf("minute %d does not match expected %d", tsMinute, tcMinute)
	}

	return nil
}

func (m *TimestampMatcher) checkSecond(ts *time.Time) error {
	value, ok := m.Value.(*Time)
	if !ok {
		return fmt.Errorf("value is not a timestamp")
	}

	if err := m.checkMinute(ts); err != nil {
		return err
	}

	tsSecond := ts.Second()
	tcSecond := value.Second()

	if tsSecond != tcSecond {
		return fmt.Errorf("second %d does not match expected %d", tsSecond, tcSecond)
	}

	return nil
}

func (m *TimestampMatcher) checkBefore(ts *time.Time) error {
	value, ok := m.Value.(*Time)
	if !ok {
		return fmt.Errorf("value is not a timestamp")
	}

	tsTime := ts
	tcTime := value.Time

	if !(tsTime.Before(tcTime) || tsTime.Equal(tcTime)) {
		return fmt.Errorf("%s is not before %s", tsTime, tcTime)
	}

	return nil
}

func (m *TimestampMatcher) checkAfter(ts *time.Time) error {
	value, ok := m.Value.(*Time)
	if !ok {
		return fmt.Errorf("value is not a timestamp")
	}

	tsTime := ts
	tcTime := value.Time

	if !(tsTime.After(tcTime) || tsTime.Equal(tcTime)) {
		return fmt.Errorf("%s is not after %s", tsTime, tcTime)
	}

	return nil
}

func (m *TimestampMatcher) checkBetween(ts *time.Time) error {
	value, ok := m.Value.(*timestampBetween)
	if !ok {
		return fmt.Errorf("value is not a timestampBetween")
	}

	if value.Before == nil || value.After == nil {
		return fmt.Errorf("value is nil")
	}

	tsTime := ts
	beforeTime := value.Before.Time
	afterTime := value.After.Time

	isBefore := tsTime.Before(beforeTime) || tsTime.Equal(beforeTime)
	isAfter := tsTime.After(afterTime) || tsTime.Equal(afterTime)

	if !(isBefore) {
		return fmt.Errorf("%s is not before %s", tsTime, beforeTime)
	}

	if !(isAfter) {
		return fmt.Errorf("%s is not after %s", tsTime, afterTime)
	}

	return nil
}

func (m *TimestampMatcher) checkFormat(ts *time.Time) error {
	value, ok := m.Value.(*timestampFormat)
	if !ok {
		return fmt.Errorf("value is not a timestampFormat")
	}

	if value.Timestamp == nil {
		return fmt.Errorf("value is nil")
	}

	tsStr := ts.Format(value.Format)
	tcStr := value.Timestamp.Format(value.Format)

	if tcStr != tsStr {
		return fmt.Errorf("%s does not match expected %s", tsStr, tcStr)
	}

	return nil
}

// TimestampMatcher matches a *timestamppb.Timestamp based on an operator and a value
type TimestampMatcher struct {
	Operator Operator       `json:"operator"`
	Value    timestampValue `json:"value"`
}

// Operator is en enum over types of TimestampMatcher
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
	case opAfter.slug:
		return opAfter, nil

	case opBefore.slug:
		return opBefore, nil

	case opBetween.slug:
		return opBetween, nil

	case opDay.slug:
		return opDay, nil

	case opFormat.slug:
		return opFormat, nil

	case opHour.slug:
		return opHour, nil

	case opMinute.slug:
		return opMinute, nil

	case opSecond.slug:
		return opSecond, nil

	default:
		return opUnknown, fmt.Errorf("Invalid value for TimestampMatcher operator: %s", str)
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
	opAfter   = Operator{"after"}
	opBefore  = Operator{"before"}
	opBetween = Operator{"between"}
	opDay     = Operator{"day"}
	opFormat  = Operator{"format"}
	opHour    = Operator{"hour"}
	opMinute  = Operator{"minute"}
	opSecond  = Operator{"second"}
)

// Match attempts to match a *timestamppb.Timestamp based on the TimestampMatcher
func (m *TimestampMatcher) Match(value *timestamppb.Timestamp) error {
	switch m.Operator {
	case opAfter:
		{
			if m.Value == nil {
				return fmt.Errorf("matcher value is nil")
			}
			if value == nil {
				return fmt.Errorf("timestamp is nil")
			}
			tsTime := value.AsTime().UTC()
			return m.checkAfter(&tsTime)
		}
	case opBefore:
		{
			if m.Value == nil {
				return fmt.Errorf("matcher value is nil")
			}
			if value == nil {
				return fmt.Errorf("timestamp is nil")
			}
			tsTime := value.AsTime().UTC()
			return m.checkBefore(&tsTime)
		}
	case opBetween:
		{
			if m.Value == nil {
				return fmt.Errorf("matcher value is nil")
			}
			if value == nil {
				return fmt.Errorf("timestamp is nil")
			}
			tsTime := value.AsTime().UTC()
			return m.checkBetween(&tsTime)
		}
	case opDay:
		{
			if m.Value == nil {
				return fmt.Errorf("matcher value is nil")
			}
			if value == nil {
				return fmt.Errorf("timestamp is nil")
			}
			tsTime := value.AsTime().UTC()
			return m.checkDay(&tsTime)
		}
	case opFormat:
		{
			if m.Value == nil {
				return fmt.Errorf("matcher value is nil")
			}
			if value == nil {
				return fmt.Errorf("timestamp is nil")
			}
			tsTime := value.AsTime().UTC()
			return m.checkFormat(&tsTime)
		}
	case opHour:
		{
			if m.Value == nil {
				return fmt.Errorf("matcher value is nil")
			}
			if value == nil {
				return fmt.Errorf("timestamp is nil")
			}
			tsTime := value.AsTime().UTC()
			return m.checkHour(&tsTime)
		}
	case opMinute:
		{
			if m.Value == nil {
				return fmt.Errorf("matcher value is nil")
			}
			if value == nil {
				return fmt.Errorf("timestamp is nil")
			}
			tsTime := value.AsTime().UTC()
			return m.checkMinute(&tsTime)
		}
	case opSecond:
		{
			if m.Value == nil {
				return fmt.Errorf("matcher value is nil")
			}
			if value == nil {
				return fmt.Errorf("timestamp is nil")
			}
			tsTime := value.AsTime().UTC()
			return m.checkSecond(&tsTime)
		}
	default:
		return fmt.Errorf("Unhandled TimestampMatcher operator %s", m.Operator)
	}
}

// Marshal implements json.Marshaler
func (m TimestampMatcher) MarshalJSON() ([]byte, error) {
	type Alias TimestampMatcher
	switch valueType := m.Value.(type) {
	case *Time:
		return json.Marshal(&struct {
			Value *Time `json:"value"`
			*Alias
		}{
			Value: valueType,
			Alias: (*Alias)(&m),
		})
	case *timestampBetween:
		return json.Marshal(&struct {
			Value *timestampBetween `json:"value"`
			*Alias
		}{
			Value: valueType,
			Alias: (*Alias)(&m),
		})
	case *timestampFormat:
		return json.Marshal(&struct {
			Value *timestampFormat `json:"value"`
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
func (m *TimestampMatcher) UnmarshalJSON(b []byte) error {
	// User just provides a plain timestampValue, so default to Second
	var rawVal Time
	err := yaml.UnmarshalStrict(b, &rawVal)
	if err == nil {
		m.Operator = opSecond
		m.Value = (timestampValue)(&rawVal)
		return nil
	}

	type Alias TimestampMatcher
	{
		temp := struct {
			Value *Time `json:"value"`
			*Alias
		}{Alias: (*Alias)(m)}
		if err := yaml.UnmarshalStrict(b, &temp); err == nil {
			m.Value = temp.Value
			return nil
		}
	}
	{
		temp := struct {
			Value *timestampBetween `json:"value"`
			*Alias
		}{Alias: (*Alias)(m)}
		if err := yaml.UnmarshalStrict(b, &temp); err == nil {
			m.Value = temp.Value
			return nil
		}
	}
	{
		temp := struct {
			Value *timestampFormat `json:"value"`
			*Alias
		}{Alias: (*Alias)(m)}
		if err := yaml.UnmarshalStrict(b, &temp); err == nil {
			m.Value = temp.Value
			return nil
		}
	}
	return fmt.Errorf("Unmarshal TimestampMatcher: Failed to unmarshal")
}

// After constructs a new TimestampMatcher that matches using the After operator
func After(value *Time) *TimestampMatcher {
	return &TimestampMatcher{
		Operator: opAfter,
		Value:    value,
	}
}

// Before constructs a new TimestampMatcher that matches using the Before operator
func Before(value *Time) *TimestampMatcher {
	return &TimestampMatcher{
		Operator: opBefore,
		Value:    value,
	}
}

// Between constructs a new TimestampMatcher that matches using the Between operator
func Between(before *Time, after *Time) *TimestampMatcher {
	return &TimestampMatcher{
		Operator: opBetween,
		Value: &timestampBetween{
			After:  after,
			Before: before,
		},
	}
}

// Day constructs a new TimestampMatcher that matches using the Day operator
func Day(value *Time) *TimestampMatcher {
	return &TimestampMatcher{
		Operator: opDay,
		Value:    value,
	}
}

// Format constructs a new TimestampMatcher that matches using the Format operator
func Format(value *Time, format string) *TimestampMatcher {
	return &TimestampMatcher{
		Operator: opFormat,
		Value: &timestampFormat{
			Timestamp: value,
			Format:    format,
		},
	}
}

// Hour constructs a new TimestampMatcher that matches using the Hour operator
func Hour(value *Time) *TimestampMatcher {
	return &TimestampMatcher{
		Operator: opHour,
		Value:    value,
	}
}

// Minute constructs a new TimestampMatcher that matches using the Minute operator
func Minute(value *Time) *TimestampMatcher {
	return &TimestampMatcher{
		Operator: opMinute,
		Value:    value,
	}
}

// Second constructs a new TimestampMatcher that matches using the Second operator
func Second(value *Time) *TimestampMatcher {
	return &TimestampMatcher{
		Operator: opSecond,
		Value:    value,
	}
}
