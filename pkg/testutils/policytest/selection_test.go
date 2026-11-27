// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"testing"

	"github.com/spf13/pflag"
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

	tests, err = (&Selection{Names: []string{".*"}}).Tests(reg)
	require.NoError(t, err)
	require.Len(t, tests, 2)

	_, err = (&Selection{Names: []string{"a-test", "nope"}}).Tests(reg)
	require.ErrorIs(t, err, errNoMatch)
	_, err = (&Selection{}).Tests(reg)
	require.ErrorIs(t, err, errNoTests)
	_, err = (&Selection{Names: []string{".*"}, AllParams: true, Params: map[string]string{"n": "1"}}).Tests(reg)
	require.ErrorIs(t, err, errParamsAndAll)
	_, err = (&Selection{Names: []string{".*"}, Params: map[string]string{"n": "a,b"}}).Tests(reg)
	require.ErrorIs(t, err, errParamChars)
	_, err = (&Selection{Names: []string{".*"}, Params: map[string]string{"n=m": "a"}}).Tests(reg)
	require.ErrorIs(t, err, errParamChars)
}

func TestSelectionArgsRoundTrip(t *testing.T) {
	for name, want := range map[string]*Selection{
		"all": {
			Names:       []string{".*"},
			AllParams:   true,
			MonitorMode: true,
		},
		"params": {
			Names:  []string{"kprobe-fd-arg", "uprobe-.*"},
			Params: map[string]string{"fd": "3", "path": "/tmp/a=b"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			args, err := want.Args()
			require.NoError(t, err)

			var got Selection
			flags := pflag.NewFlagSet("run", pflag.ContinueOnError)
			got.AddFlags(flags)
			require.NoError(t, flags.Parse(args))
			got.Names = flags.Args()
			require.Equal(t, want, &got)
		})
	}
}
