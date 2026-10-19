// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"errors"
	"fmt"
	"iter"
	"maps"
	"slices"
	"strings"

	"github.com/spf13/pflag"
)

// Selection is the set of policy tests to run and how to run them.
type Selection struct {
	// Names of the tests to run, regular expressions for GetByRegexps; every
	// one has to match a test.
	Names []string
	// Params sets parameter values for every test.
	Params map[string]string
	// AllParams runs every test once per combination of its parameter values.
	AllParams   bool
	MonitorMode bool
}

var (
	errNoTests      = errors.New("no tests selected")
	errParamsAndAll = errors.New("parameter values conflict with running all parameter sets")
	errParamChars   = errors.New("parameter names and values cannot contain commas or quotes, nor names an equals sign")
	errNoMatch      = errors.New("no policy tests matching")
)

// AddFlags registers the flags that fill the selection, with its current
// values as the defaults. Names come from the positional arguments.
func (s *Selection) AddFlags(flags *pflag.FlagSet) {
	flags.BoolVar(&s.AllParams, "all-params", s.AllParams, "Run policy tests using all available parameters")
	flags.BoolVar(&s.MonitorMode, "monitor-mode", s.MonitorMode, "set the policy(-ies) in monitor mode before running the test(s)")
	flags.StringToStringVar(&s.Params, "set-param", s.Params, "Set a policy parameter")
}

// Validate checks that the selection is consistent and that a remote tetra
// reads Args back unchanged. Tests and Args call it.
func (s *Selection) Validate() error {
	switch {
	case len(s.Names) == 0:
		return errNoTests
	case s.AllParams && len(s.Params) > 0:
		return errParamsAndAll
	}
	// pflag reads a --set-param with more than one '=' as CSV
	for k, v := range s.Params {
		if strings.ContainsAny(k, `,"=`) || strings.ContainsAny(v, `,"`) {
			return fmt.Errorf("%w: %s", errParamChars, k)
		}
	}
	return nil
}

// Tests returns the selected tests, sorted by name.
func (s *Selection) Tests(reg *RegisteredPolicyTests) ([]*T, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	tests, err := reg.GetByRegexps(s.Names)
	if err != nil {
		return nil, err
	}
	for _, name := range s.Names {
		if matched, _ := reg.GetByRegexps([]string{name}); len(matched) == 0 {
			return nil, fmt.Errorf("%w %q, see `tetra policytest list`", errNoMatch, name)
		}
	}
	return tests, nil
}

// ParamValues yields the parameter values to run t with.
func (s *Selection) ParamValues(t *T) iter.Seq[ParamVals] {
	if s.AllParams {
		return t.AllParamValues()
	}
	vals := newParamVals()
	for k, v := range s.Params {
		vals[k] = v
	}
	return func(yield func(ParamVals) bool) {
		yield(vals)
	}
}

// Runs returns how many times the tests run: once per parameter set.
func (s *Selection) Runs(tests []*T) int {
	n := 0
	for _, t := range tests {
		for range s.ParamValues(t) {
			n++
		}
	}
	return n
}

// Args returns the arguments of a `tetra policytest run` that runs the same
// selection, for runners that start tetra somewhere else.
func (s *Selection) Args() ([]string, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	var args []string
	if s.AllParams {
		args = append(args, "--all-params")
	}
	if s.MonitorMode {
		args = append(args, "--monitor-mode")
	}
	for _, k := range slices.Sorted(maps.Keys(s.Params)) {
		args = append(args, "--set-param="+k+"="+s.Params[k])
	}
	return append(append(args, "--"), s.Names...), nil
}
