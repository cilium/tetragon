// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package fieldfilters

import (
	"regexp"
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedactString_Simple(t *testing.T) {
	re := regexp.MustCompile(`(ab)cd`)

	s := "abcd"
	assert.Equal(t, REDACTION_STR+"cd", redactString(re, s))

	s = "cdef"
	assert.Equal(t, "cdef", redactString(re, s))

	s = "abef"
	assert.Equal(t, "abef", redactString(re, s))

	s = "innocent"
	assert.Equal(t, "innocent", redactString(re, s))
}

func TestRedactString_NonCapturing(t *testing.T) {
	re := regexp.MustCompile(`(?:--password|-p)\s+(\S+)`)

	s := "--password fooBarQuxBaz!"
	assert.Equal(t, "--password "+REDACTION_STR, redactString(re, s))

	s = "-p fooBarQuxBaz!"
	assert.Equal(t, "-p "+REDACTION_STR, redactString(re, s))

	s = "innocent"
	assert.Equal(t, "innocent", redactString(re, s))
}

func TestRedactString_Nested(t *testing.T) {
	re := regexp.MustCompile(`(foo(bar))qux`)

	s := "foobarqux"
	assert.Equal(t, REDACTION_STR+"qux", redactString(re, s))

	s = "innocent"
	assert.Equal(t, "innocent", redactString(re, s))
}

func TestRedact_ExecFilter(t *testing.T) {
	event := &tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExec{
			ProcessExec: &tetragon.ProcessExec{
				Process: &tetragon.Process{
					Arguments: "--verbsose=true --password ybx511!ackt544 --username foobar",
				},
			},
		},
	}

	filterList := `{"redact": ["(?:--password|-p)[\\s=]+(\\S+)"]}`
	filters, err := ParseRedactionFilterList(filterList)
	require.NoError(t, err)

	filters.Redact(event)
	assert.Equal(t, "--verbsose=true --password "+REDACTION_STR+" --username foobar", event.GetProcessExec().Process.Arguments)
}

func TestRedact_NoFilter(t *testing.T) {
	event := &tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExec{
			ProcessExec: &tetragon.ProcessExec{
				Process: &tetragon.Process{
					Arguments: "--verbsose=true --password ybx511!ackt544 --username foobar",
				},
			},
		},
	}

	filterList := `{"match": [{"event_set": ["PROCESS_EXEC"]}], "redact": ["(?:--password|-p)[\\s=]+(\\S+)"]}`
	filters, err := ParseRedactionFilterList(filterList)
	require.NoError(t, err)

	filters.Redact(event)
	assert.Equal(t, "--verbsose=true --password "+REDACTION_STR+" --username foobar", event.GetProcessExec().Process.Arguments)
}

func TestRedact_Multi(t *testing.T) {
	event := &tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExec{
			ProcessExec: &tetragon.ProcessExec{
				Process: &tetragon.Process{
					Arguments: "--verbsose=true --password ybx511!ackt544 --username foobar",
				},
				Parent: &tetragon.Process{
					Arguments: "cheesecake TOPSECRET innocent",
				},
			},
		},
	}

	filterList := `{"match": [{"event_set": ["PROCESS_EXEC"]}], "redact": ["(?:--password|-p)[\\s=]+(\\S+)", "\\W(TOPSECRET)\\W", "(cheese)cake"]}`
	filters, err := ParseRedactionFilterList(filterList)
	require.NoError(t, err)

	filters.Redact(event)
	assert.Equal(t, "--verbsose=true --password "+REDACTION_STR+" --username foobar", event.GetProcessExec().Process.Arguments)
	assert.Equal(t, REDACTION_STR+"cake "+REDACTION_STR+" innocent", event.GetProcessExec().Parent.Arguments)
}

func TestRedact_ParsedMultiStep(t *testing.T) {
	filterList := `{"match": [{"event_set": ["PROCESS_EXEC"]}], "redact": ["\\W(passwd)\\W?"]}
	{"match": [{"binary_regex": ["passwd"]}], "redact": ["(?:-p|--password)(?:\\s+|=)(\\S*)"]}`
	filters, err := ParseRedactionFilterList(filterList)
	require.NoError(t, err)

	event := &tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExec{
			ProcessExec: &tetragon.ProcessExec{
				Process: &tetragon.Process{
					Binary:    "/bin/passwd",
					Arguments: "-p foobarQux1337",
				},
			},
		},
	}

	filters.Redact(event)

	assert.Equal(t, "/bin/"+REDACTION_STR, event.GetProcessExec().Process.Binary)
	assert.Equal(t, "-p "+REDACTION_STR, event.GetProcessExec().Process.Arguments)
}
