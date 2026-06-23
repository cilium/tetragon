// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package kube

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestToResults(t *testing.T) {
	results := []TestResult{
		{Name: "t1", Scenarios: []ScenarioResult{{Name: "s1"}}},
		{Name: "t2", Err: "boom"},
		{Name: "t3", Skipped: "old kernel", Scenarios: []ScenarioResult{{Name: "s3", CheckerErr: "no match"}}},
	}

	names, out := ToResults(results)
	require.Equal(t, []string{"t1", "t2", "t3"}, names)
	require.Len(t, out, 3)

	// passing test: no errors reconstructed
	assert.NoError(t, out[0].Err)
	assert.NoError(t, out[0].ScenariosRes[0].Err())

	// test-level error reconstructed from string
	require.Error(t, out[1].Err)
	assert.Equal(t, "boom", out[1].Err.Error())

	// skipped + scenario error
	assert.Equal(t, "old kernel", out[2].Skipped)
	require.Error(t, out[2].ScenariosRes[0].CheckerErr)
	assert.Equal(t, "no match", out[2].ScenariosRes[0].CheckerErr.Error())
}
