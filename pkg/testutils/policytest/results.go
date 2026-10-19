// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
)

// Output formats of WriteResults
const (
	OutputText = "text"
	OutputJSON = "json"
)

// a result line carries the error strings of every scenario
const maxResultLine = 1 << 20

var (
	errNoResult      = errors.New("result line without a result")
	errUnknownFormat = errors.New("unknown output format")
)

// WriteResults writes each result to out as it arrives, as text or as JSON
// lines, and returns an error when a result failed or the sequence did.
func WriteResults(out io.Writer, format string, results iter.Seq2[*NamedResult, error]) error {
	var write func(*NamedResult) error
	switch format {
	case OutputJSON:
		enc := json.NewEncoder(out)
		write = func(res *NamedResult) error { return enc.Encode(res) }
	case OutputText:
		write = func(res *NamedResult) error {
			DumpResults(out, []*NamedResult{res})
			return nil
		}
	default:
		return fmt.Errorf("%w: %q", errUnknownFormat, format)
	}

	summary := NewResultsSummary()
	for res, err := range results {
		if err != nil {
			return err
		}
		summary.Update(res.Result)
		if err := write(res); err != nil {
			return fmt.Errorf("failed to write result: %w", err)
		}
	}
	return summary.Err()
}

// DecodeResults yields the results that `tetra policytest run --output json`
// wrote to r, one JSON object per line. Other lines are log output and are
// copied to logs when it is not nil. A line over 1 MiB, or a line that starts
// with '{' but is no result, ends the sequence with an error.
func DecodeResults(r io.Reader, logs io.Writer) iter.Seq2[*NamedResult, error] {
	return func(yield func(*NamedResult, error) bool) {
		sc := bufio.NewScanner(r)
		sc.Buffer(nil, maxResultLine)
		for sc.Scan() {
			line := sc.Bytes()
			if len(line) == 0 || line[0] != '{' {
				if logs != nil {
					fmt.Fprintf(logs, "%s\n", line)
				}
				continue
			}
			var res NamedResult
			if err := json.Unmarshal(line, &res); err != nil {
				yield(nil, fmt.Errorf("failed to decode result line: %w", err))
				return
			}
			if res.Result == nil {
				yield(nil, fmt.Errorf("%w: %s", errNoResult, line))
				return
			}
			if !yield(&res, nil) {
				return
			}
		}
		if err := sc.Err(); err != nil {
			yield(nil, fmt.Errorf("failed to read results: %w", err))
		}
	}
}
