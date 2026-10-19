// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func encodeResult(t *testing.T, res *NamedResult) string {
	b, err := json.Marshal(res)
	require.NoError(t, err)
	return string(b) + "\n"
}

func TestDecodeResults(t *testing.T) {
	passed := &NamedResult{
		Name: "kprobe-lseek ()",
		Result: &Result{
			ScenariosRes: []ScenarioRes{{Name: "lseek"}},
			TotalTime:    time.Second,
		},
	}
	failed := &NamedResult{
		Name: "kprobe-fd-arg (fd=3)",
		Result: &Result{
			ScenariosRes: []ScenarioRes{{
				Name:       "open",
				CheckerErr: JSONError{Err: errors.New("no event")},
			}},
		},
	}
	skipped := &NamedResult{Name: "usdt-set ()", Result: &Result{Skipped: "no usdt"}}

	stream := encodeResult(t, passed) + encodeResult(t, failed) + encodeResult(t, skipped)

	got, err := DecodeResults(strings.NewReader(stream))
	require.NoError(t, err)
	require.Len(t, got, 3)
	require.Equal(t, passed.Name, got[0].Name)
	require.Equal(t, time.Second, got[0].Result.TotalTime)
	require.NoError(t, got[0].Result.ScenariosRes[0].Err())
	require.EqualError(t, got[1].Result.ScenariosRes[0].CheckerErr, "no event")
	require.Equal(t, "no usdt", got[2].Result.Skipped)

	// a run that died halfway leaves a truncated last line
	got, err = DecodeResults(strings.NewReader(stream + `{"name": "kprobe-`))
	require.Error(t, err)
	require.Len(t, got, 3)
}

func TestDecodeResultsNoResult(t *testing.T) {
	got, err := DecodeResults(strings.NewReader(`{"name": "x"}` + "\n"))
	require.ErrorIs(t, err, errNoResult)
	require.Empty(t, got)
}

func TestWriteResults(t *testing.T) {
	results := []*NamedResult{
		{Name: "a ()", Result: &Result{ScenariosRes: []ScenarioRes{{Name: "s"}}}},
		{Name: "b ()", Result: &Result{Err: JSONError{Err: errors.New("boom")}}},
	}

	var out strings.Builder
	require.NoError(t, WriteResults(&out, OutputJSON, results))
	decoded, err := DecodeResults(strings.NewReader(out.String()))
	require.NoError(t, err)
	require.Len(t, decoded, 2)
	require.Equal(t, "b ()", decoded[1].Name)

	require.ErrorIs(t, WriteResults(&out, "yaml", results), errUnknownFormat)
}
