// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"bytes"
	"encoding/json"
	"errors"
	"iter"
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

	stream := "level=warn msg=\"Could not find BPF map root\"\n" +
		encodeResult(t, passed) +
		"\n" +
		encodeResult(t, failed) +
		"time=now level=info msg=done\n" +
		encodeResult(t, skipped)

	var logs bytes.Buffer
	var got []*NamedResult
	for res, err := range DecodeResults(strings.NewReader(stream), &logs) {
		require.NoError(t, err)
		got = append(got, res)
	}

	require.Len(t, got, 3)
	require.Equal(t, passed.Name, got[0].Name)
	require.Equal(t, time.Second, got[0].Result.TotalTime)
	require.NoError(t, got[0].Result.ScenariosRes[0].Err())
	require.EqualError(t, got[1].Result.ScenariosRes[0].CheckerErr, "no event")
	require.Equal(t, "no usdt", got[2].Result.Skipped)
	require.Equal(t, "level=warn msg=\"Could not find BPF map root\"\n\ntime=now level=info msg=done\n", logs.String())

	summary := NewResultsSummary()
	for _, res := range got {
		summary.Update(res.Result)
	}
	require.Equal(t, ResultsSummary{Total: 3, Skipped: 1, Errs: 1}, *summary)
}

func TestDecodeResultsErrors(t *testing.T) {
	for name, stream := range map[string]string{
		"bad json":  `{"name": "x", "result": }` + "\n",
		"no result": `{"name": "x"}` + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			var got []*NamedResult
			var gotErr error
			for res, err := range DecodeResults(strings.NewReader(stream), nil) {
				if err != nil {
					gotErr = err
					break
				}
				got = append(got, res)
			}
			require.Error(t, gotErr)
			require.Empty(t, got)
		})
	}
}

func seqOf(results []*NamedResult, err error) iter.Seq2[*NamedResult, error] {
	return func(yield func(*NamedResult, error) bool) {
		for _, res := range results {
			if !yield(res, nil) {
				return
			}
		}
		if err != nil {
			yield(nil, err)
		}
	}
}

func TestWriteResults(t *testing.T) {
	results := []*NamedResult{
		{Name: "a ()", Result: &Result{ScenariosRes: []ScenarioRes{{Name: "s"}}}},
		{Name: "b ()", Result: &Result{Err: JSONError{Err: errors.New("boom")}}},
	}

	var out bytes.Buffer
	err := WriteResults(&out, OutputJSON, seqOf(results, nil))
	require.EqualError(t, err, "result errors: 1/2")
	var decoded []*NamedResult
	for res, err := range DecodeResults(&out, nil) {
		require.NoError(t, err)
		decoded = append(decoded, res)
	}
	require.Len(t, decoded, 2)
	require.Equal(t, "b ()", decoded[1].Name)
	require.EqualError(t, decoded[1].Result.Err, "boom")

	out.Reset()
	require.NoError(t, WriteResults(&out, OutputText, seqOf(results[:1], nil)))
	require.Contains(t, out.String(), "P: a ()")
	require.Contains(t, out.String(), "1/1 scenario(s) succeeded")

	out.Reset()
	seqErr := errors.New("pod gone")
	require.ErrorIs(t, WriteResults(&out, OutputJSON, seqOf(results[:1], seqErr)), seqErr)
	require.Equal(t, 1, strings.Count(out.String(), "\n"), "the result before the error is written")

	require.ErrorIs(t, WriteResults(&out, "yaml", seqOf(nil, nil)), errUnknownFormat)
}

func TestDecodeResultsStops(t *testing.T) {
	res := &NamedResult{Name: "a ()", Result: &Result{}}
	stream := encodeResult(t, res) + encodeResult(t, res)
	n := 0
	for _, err := range DecodeResults(strings.NewReader(stream), nil) {
		require.NoError(t, err)
		n++
		break
	}
	require.Equal(t, 1, n)
}
