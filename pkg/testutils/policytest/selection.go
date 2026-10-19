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
)

// Selection is the set of policy tests to run and how to run them.
type Selection struct {
	// Names of the tests to run.
	Names []string
	// AllTests runs every registered test instead of Names.
	AllTests bool
	// Params sets parameter values for every test.
	Params map[string]string
	// AllParams runs every test once per combination of its parameter values.
	AllParams bool
	// MonitorMode loads the policies in monitor mode.
	MonitorMode bool
}

var (
	errNoTests      = errors.New("no tests selected")
	errNamesAndAll  = errors.New("test names conflict with running all tests")
	errParamsAndAll = errors.New("parameter values conflict with running all parameter sets")
	errParamChars   = errors.New("parameter names and values cannot contain commas or quotes, nor names an equals sign")
	errUnknownTest  = errors.New("unknown policy test")
)

// Validate checks that the selection is consistent and that Args renders it
// so that a remote tetra reads it back unchanged.
func (s *Selection) Validate() error {
	switch {
	case s.AllTests && len(s.Names) > 0:
		return errNamesAndAll
	case !s.AllTests && len(s.Names) == 0:
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
	if s.AllTests {
		return reg.GetByFunction(func(*T) bool { return true }), nil
	}
	tests := reg.GetByFunction(func(t *T) bool { return slices.Contains(s.Names, t.Name) })
	for _, name := range s.Names {
		if !slices.ContainsFunc(tests, func(t *T) bool { return t.Name == name }) {
			return nil, fmt.Errorf("%w: %q", errUnknownTest, name)
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

// Args returns the arguments of a `tetra policytest run` that runs the same
// selection, for runners that start tetra somewhere else.
func (s *Selection) Args() []string {
	var args []string
	if s.AllTests {
		args = append(args, "--all-tests")
	}
	if s.AllParams {
		args = append(args, "--all-params")
	}
	if s.MonitorMode {
		args = append(args, "--monitor-mode")
	}
	for _, k := range slices.Sorted(maps.Keys(s.Params)) {
		args = append(args, "--set-param="+k+"="+s.Params[k])
	}
	return append(append(args, "--"), s.Names...)
}
