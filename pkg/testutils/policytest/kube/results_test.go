// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package kube

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/testutils/policytest"
)

func TestResultsRoundTrip(t *testing.T) {
	results := []TestResult{
		{Name: "t1", Scenarios: []ScenarioResult{{Name: "s1"}}},
		{Name: "t2", Err: "boom", Scenarios: []ScenarioResult{{Name: "s2", CheckerErr: "mismatch"}}},
		{Name: "t3", Skipped: "kernel too old"},
	}

	data, err := Encode(results)
	require.NoError(t, err)

	got, err := Decode(data)
	require.NoError(t, err)
	assert.Equal(t, results, got)
}

func TestExtractResults(t *testing.T) {
	data, err := Encode([]TestResult{{Name: "t1", Scenarios: []ScenarioResult{{Name: "s1"}}}})
	require.NoError(t, err)

	// pod logs interleave slog (stderr) with the stdout result line
	logs := []byte("level=warn msg=\"Could not find BPF map root\"\n" +
		ResultMarker + string(data) + "\n" +
		"level=info msg=\"done\"\n")

	got, err := ExtractResults(logs)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "t1", got[0].Name)
}

func TestExtractResults_NoMarker(t *testing.T) {
	_, err := ExtractResults([]byte("level=warn msg=\"only noise\"\n"))
	require.Error(t, err)
}

func TestFromResult(t *testing.T) {
	r := &policytest.Result{
		Err: errors.New("load failed"),
		ScenariosRes: []policytest.ScenarioRes{
			{Name: "s1", CheckerErr: errors.New("no match")},
		},
	}

	tr := FromResult("mytest", r)
	assert.Equal(t, "mytest", tr.Name)
	assert.Equal(t, "load failed", tr.Err)
	require.Len(t, tr.Scenarios, 1)
	assert.Equal(t, "s1", tr.Scenarios[0].Name)
	assert.Equal(t, "no match", tr.Scenarios[0].CheckerErr)
	assert.True(t, tr.Failed())
}

func TestTestResultFailed(t *testing.T) {
	tests := []struct {
		name string
		tr   TestResult
		want bool
	}{
		{"pass", TestResult{Name: "ok", Scenarios: []ScenarioResult{{Name: "s"}}}, false},
		{"skipped is not a failure", TestResult{Name: "skip", Skipped: "reason"}, false},
		{"test-level error", TestResult{Name: "err", Err: "x"}, true},
		{"scenario trigger error", TestResult{Scenarios: []ScenarioResult{{TriggerErr: "x"}}}, true},
		{"scenario checker error", TestResult{Scenarios: []ScenarioResult{{CheckerErr: "x"}}}, true},
		{"scenario action-counts error", TestResult{Scenarios: []ScenarioResult{{ActionCountsErr: "x"}}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.tr.Failed())
		})
	}
}
