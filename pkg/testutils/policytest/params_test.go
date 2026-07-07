// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"maps"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAllParamsValues(t *testing.T) {
	params := []Parameter{
		{Name: "a", Values: []any{"a1", "a2"}},
		{Name: "b", Values: []any{"b1", "b2", "b3"}},
	}
	expected := []ParamVals{
		{"a": "a1", "b": "b1"},
		{"a": "a1", "b": "b2"},
		{"a": "a1", "b": "b3"},
		{"a": "a2", "b": "b1"},
		{"a": "a2", "b": "b2"},
		{"a": "a2", "b": "b3"},
	}
	ret := make([]ParamVals, 0)
	for vs := range allParamValues(params) {
		ret = append(ret, maps.Clone(vs))
	}
	require.ElementsMatch(t, expected, ret)
}
