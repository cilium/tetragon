// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetByRegexps(t *testing.T) {
	rpt := &RegisteredPolicyTests{}
	for _, name := range []string{"uprobe-generic", "uprobe-override", "kprobe-uprobe", "lsm-dup-hooks"} {
		rpt.tests = append(rpt.tests, &T{Name: name})
	}

	tcs := []struct {
		name     string
		exprs    []string
		expected []string
		wantErr  bool
	}{
		{
			name:     "exact name",
			exprs:    []string{"uprobe-generic"},
			expected: []string{"uprobe-generic"},
		},
		{
			name:  "partial name does not match",
			exprs: []string{"uprobe"},
		},
		{
			name:     "prefix",
			exprs:    []string{"uprobe-.*"},
			expected: []string{"uprobe-generic", "uprobe-override"},
		},
		{
			name:     "substring",
			exprs:    []string{".*uprobe.*"},
			expected: []string{"kprobe-uprobe", "uprobe-generic", "uprobe-override"},
		},
		{
			// both alternatives have to match the whole name, so "uprobe" does not match
			// "kprobe-uprobe"
			name:     "alternation",
			exprs:    []string{"lsm-dup-hooks|uprobe"},
			expected: []string{"lsm-dup-hooks"},
		},
		{
			name:     "alternation in group",
			exprs:    []string{"uprobe-(generic|override)"},
			expected: []string{"uprobe-generic", "uprobe-override"},
		},
		{
			name:     "multiple expressions",
			exprs:    []string{"lsm-.*", "uprobe-generic", "uprobe-gen.*"},
			expected: []string{"lsm-dup-hooks", "uprobe-generic"},
		},
		{
			name:  "no expressions",
			exprs: nil,
		},
		{
			name:    "invalid expression",
			exprs:   []string{"uprobe-("},
			wantErr: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			tests, err := rpt.GetByRegexps(tc.exprs)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			var names []string
			for _, test := range tests {
				names = append(names, test.Name)
			}
			require.Equal(t, tc.expected, names)
		})
	}
}
