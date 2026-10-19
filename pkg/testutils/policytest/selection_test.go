// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

func selectionRegistry() *RegisteredPolicyTests {
	return &RegisteredPolicyTests{tests: []*T{
		{Name: "b-test"},
		{Name: "a-test", Params: []Parameter{{Name: "n", Default: 1, Values: []any{1, 2}}}},
	}}
}

func testNames(tests []*T) []string {
	var names []string
	for _, t := range tests {
		names = append(names, t.Name)
	}
	return names
}

func TestSelectionTests(t *testing.T) {
	reg := selectionRegistry()

	tests, err := (&Selection{Names: []string{"b-test", "a-test"}}).Tests(reg)
	require.NoError(t, err)
	require.Equal(t, []string{"a-test", "b-test"}, testNames(tests))

	tests, err = (&Selection{Names: []string{"b-test"}}).Tests(reg)
	require.NoError(t, err)
	require.Equal(t, []string{"b-test"}, testNames(tests))

	tests, err = (&Selection{AllTests: true}).Tests(reg)
	require.NoError(t, err)
	require.Len(t, tests, 2)

	_, err = (&Selection{Names: []string{"a-test", "nope"}}).Tests(reg)
	require.ErrorIs(t, err, errUnknownTest)
	_, err = (&Selection{}).Tests(reg)
	require.ErrorIs(t, err, errNoTests)
	_, err = (&Selection{AllTests: true, Names: []string{"a-test"}}).Tests(reg)
	require.ErrorIs(t, err, errNamesAndAll)
	_, err = (&Selection{AllTests: true, AllParams: true, Params: map[string]string{"n": "1"}}).Tests(reg)
	require.ErrorIs(t, err, errParamsAndAll)
	_, err = (&Selection{AllTests: true, Params: map[string]string{"n": "a,b"}}).Tests(reg)
	require.ErrorIs(t, err, errParamChars)
	_, err = (&Selection{AllTests: true, Params: map[string]string{"n=m": "a"}}).Tests(reg)
	require.ErrorIs(t, err, errParamChars)
	_, err = (&Selection{AllTests: true, Params: map[string]string{"path": "/tmp/a=b"}}).Tests(reg)
	require.NoError(t, err, "an equals sign in a value survives the round trip")
}

func TestSelectionParamValues(t *testing.T) {
	a := selectionRegistry().tests[1]

	vals := slices.Collect((&Selection{Params: map[string]string{"n": "2"}}).ParamValues(a))
	require.Equal(t, []ParamVals{{"n": "2"}}, vals)

	vals = slices.Collect((&Selection{}).ParamValues(a))
	require.Equal(t, []ParamVals{{}}, vals)

	// allParamValues reuses one map, so copy the value out of each iteration
	var got []any
	for v := range (&Selection{AllParams: true}).ParamValues(a) {
		got = append(got, v["n"])
	}
	require.ElementsMatch(t, []any{1, 2}, got)
}

func TestSelectionRuns(t *testing.T) {
	tests := selectionRegistry().tests
	require.Equal(t, 2, (&Selection{AllTests: true}).Runs(tests))
	require.Equal(t, 3, (&Selection{AllTests: true, AllParams: true}).Runs(tests))
}

func TestSelectionArgs(t *testing.T) {
	sel := &Selection{
		Names:       []string{"a-test", "b-test"},
		AllParams:   true,
		MonitorMode: true,
		Params:      map[string]string{"z": "1", "a": "2"},
	}
	require.Equal(t, []string{
		"--all-params", "--monitor-mode", "--set-param=a=2", "--set-param=z=1",
		"--", "a-test", "b-test",
	}, sel.Args())
	require.Equal(t, []string{"--all-tests", "--"}, (&Selection{AllTests: true}).Args())
}
