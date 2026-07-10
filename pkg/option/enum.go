// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package option

import (
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/pflag"
)

var _ pflag.Value = &Enum{}

type Enum struct {
	allowed []string
	Value   string
}

func NewEnum(allowed []string, d string) (*Enum, error) {
	e := Enum{
		allowed: allowed,
		Value:   d,
	}
	if !slices.Contains(allowed, d) {
		return nil, fmt.Errorf("invalid default value %s, please provide one of %s", d, e.Allowed())
	}
	return &e, nil
}

func (e *Enum) String() string {
	return e.Value
}

func (e *Enum) Allowed() string {
	return fmt.Sprintf("(%s)", strings.Join(e.allowed, ", "))
}

func (e *Enum) Set(p string) error {
	if !slices.Contains(e.allowed, p) {
		return fmt.Errorf("invalid argument %s, please provide one of %s", p, e.Allowed())
	}
	e.Value = p
	return nil
}

func (e *Enum) Type() string {
	return "string"
}

var _ pflag.Value = &SliceEnum{}

type SliceEnum struct {
	allowed []string
	Values  []string
}

func NewSliceEnum(allowed []string, d []string) (*SliceEnum, error) {
	e := SliceEnum{
		allowed: allowed,
		Values:  d,
	}
	for _, dd := range d {
		if !slices.Contains(allowed, dd) {
			return nil, fmt.Errorf("invalid default value %s, please provide one of %s", dd, e.Allowed())
		}
	}
	return &e, nil
}

func (e *SliceEnum) String() string {
	return strings.Join(e.Values, ",")
}

func (e *SliceEnum) Allowed() string {
	return fmt.Sprintf("(%s)", strings.Join(e.allowed, ", "))
}

func (e *SliceEnum) Set(p string) error {
	if !slices.Contains(e.allowed, p) {
		return fmt.Errorf("invalid argument %s, please provide one of %s", p, e.Allowed())
	}
	e.Values = append(e.Values, p)
	return nil
}

func (e *SliceEnum) Type() string {
	return "sliceString"
}
