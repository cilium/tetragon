// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package errmetrics

import (
	"encoding/json/v2"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDumpEntryJSON(t *testing.T) {
	// zero numbers are omitted, as the json output of "tetra debug dump errmetrics" always did
	b, err := json.Marshal([]DumpEntry{
		{FileName: "bpf_execve_event.c", LineNumber: 42, ErrorName: "ENOENT", Error: 2, Count: 3},
		{HelperFunc: "FnMapLookupElem"},
	})
	require.NoError(t, err)
	assert.JSONEq(t, `[
		{"file_name": "bpf_execve_event.c", "line_numer": 42, "error_name": "ENOENT", "error": 2, "count": 3},
		{"helper_func": "FnMapLookupElem"}
	]`, string(b))

	// an empty map dumps as an empty array, not null
	b, err = json.Marshal([]DumpEntry(nil))
	require.NoError(t, err)
	assert.Equal(t, "[]", string(b))
}
