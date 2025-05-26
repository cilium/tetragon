// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package fieldfilters

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFixupSnakeCaseString(t *testing.T) {
	s := "process.exec_id,process.binary,parent.exec_id,foo.bar_qux_baz,this_is_a_test"
	expected := "process.execId,process.binary,parent.execId,foo.barQuxBaz,thisIsATest"

	assert.Equal(t, expected, fixupSnakeCaseString(s, false))
}

func TestParseFieldFilterList(t *testing.T) {
	filters, err := ParseFieldFilterList(`{"event_set":["PROCESS_EXEC","PROCESS_EXIT"], "fields":"process.start_time,process.binary,process.arguments,process.cap,process.ns,parent.binary", "action":"INCLUDE"}
{"event_set":["PROCESS_KPROBE"], "fields":"process.start_time,process.binary,process.arguments,process.cap,process.ns,parent.binary,function_name", "action":"INCLUDE"}`)
	require.NoError(t, err, "must parse")
	assert.Equal(t, "process.start_time", filters[0].Fields.Paths[0])
}
