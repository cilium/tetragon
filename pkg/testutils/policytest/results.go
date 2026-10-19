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

// WriteResults writes the results to out, as text or as JSON lines.
func WriteResults(out io.Writer, format string, results []*NamedResult) error {
	switch format {
	case OutputJSON:
		enc := json.NewEncoder(out)
		for _, res := range results {
			if err := enc.Encode(res); err != nil {
				return fmt.Errorf("failed to write result: %w", err)
			}
		}
	case OutputText:
		DumpResults(out, results)
	default:
		return fmt.Errorf("%w: %q", errUnknownFormat, format)
	}
	return nil
}

// DecodeResults decodes the results that `tetra policytest run --output json`
// wrote to r, one per line. A line over 1 MiB, or one that holds no result,
// ends the decoding with an error and the results before it.
func DecodeResults(r io.Reader) ([]*NamedResult, error) {
	var results []*NamedResult
	sc := bufio.NewScanner(r)
	sc.Buffer(nil, maxResultLine)
	for sc.Scan() {
		var res NamedResult
		if err := json.Unmarshal(sc.Bytes(), &res); err != nil {
			return results, fmt.Errorf("failed to decode result line: %w", err)
		}
		if res.Result == nil {
			return results, fmt.Errorf("%w: %s", errNoResult, sc.Bytes())
		}
		results = append(results, &res)
	}
	if err := sc.Err(); err != nil {
		return results, fmt.Errorf("failed to read results: %w", err)
	}
	return results, nil
}
