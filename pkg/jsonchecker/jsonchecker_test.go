// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package jsonchecker

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
)

func TestJsonCheck(t *testing.T) {
	const (
		execA = `{"process_exec":{"process":{"binary":"/bin/a"}}}`
		execB = `{"process_exec":{"process":{"binary":"/bin/b"}}}`
	)

	tests := []struct {
		name      string
		content   string
		wantCount int  // events seen before giving up, for a JsonEOFError
		wantEOF   bool // a JsonEOFError, so the caller retries
		wantErrIs error
		wantErr   bool
	}{
		{name: "match", content: execA + "\n" + execB + "\n"},
		{name: "match without newlines", content: execA + execB},
		{name: "no match", content: execA + "\n" + execA + "\n", wantErr: true, wantEOF: true, wantCount: 2},
		{name: "empty file", content: "", wantErr: true, wantEOF: true, wantCount: 0},
		{name: "truncated last event", content: execA + "\n" + `{"process_exec":{"proc`, wantErr: true, wantEOF: true, wantCount: 1, wantErrIs: io.ErrUnexpectedEOF},
		{name: "last event misses closing brace", content: execA + "\n" + execB[:len(execB)-1], wantErr: true, wantEOF: true, wantCount: 1, wantErrIs: io.ErrUnexpectedEOF},
		{name: "invalid JSON", content: execA + "\nnot json\n", wantErr: true},
		{name: "unknown field", content: `{"no_such_event":{}}` + "\n", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fname := filepath.Join(t.TempDir(), "events.json")
			require.NoError(t, os.WriteFile(fname, []byte(tt.content), 0o600))
			f, err := os.Open(fname)
			require.NoError(t, err)
			defer f.Close()

			checker := ec.NewUnorderedEventChecker(
				ec.NewProcessExecChecker("b").WithProcess(ec.NewProcessChecker().WithBinary(sm.Full("/bin/b"))),
			)
			err = JsonCheck(f, checker, slog.New(slog.DiscardHandler))
			if !tt.wantErr {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)

			var eofErr *JsonEOFError
			if !tt.wantEOF {
				assert.NotErrorAs(t, err, &eofErr)
				return
			}
			require.ErrorAs(t, err, &eofErr)
			assert.Equal(t, tt.wantCount, eofErr.count)
			if tt.wantErrIs != nil {
				assert.ErrorIs(t, err, tt.wantErrIs)
			}
		})
	}
}
