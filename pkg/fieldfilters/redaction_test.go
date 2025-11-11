// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package fieldfilters

import (
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedactString_Simple(t *testing.T) {
	re := regexp.MustCompile(`(ab)cd`)

	s := "abcd"
	res, modified := redactString(re, s)
	assert.Equal(t, REDACTION_STR+"cd", res)
	assert.True(t, modified)

	s = "cdef"
	res, modified = redactString(re, s)
	assert.Equal(t, "cdef", res)
	assert.False(t, modified)

	s = "abef"
	res, modified = redactString(re, s)
	assert.Equal(t, "abef", res)
	assert.False(t, modified)

	s = "innocent"
	res, modified = redactString(re, s)
	assert.Equal(t, "innocent", res)
	assert.False(t, modified)
}

func TestRedactString_NonCapturing(t *testing.T) {
	re := regexp.MustCompile(`(?:--password|-p)\s+(\S+)`)

	s := "--password fooBarQuxBaz!"
	res, modified := redactString(re, s)
	assert.Equal(t, "--password "+REDACTION_STR, res)
	assert.True(t, modified)

	s = "-p fooBarQuxBaz!"
	res, modified = redactString(re, s)
	assert.Equal(t, "-p "+REDACTION_STR, res)
	assert.True(t, modified)

	s = "innocent"
	res, modified = redactString(re, s)
	assert.Equal(t, "innocent", res)
	assert.False(t, modified)
}

func TestRedactString_Nested(t *testing.T) {
	re := regexp.MustCompile(`(foo(bar))qux`)

	s := "foobarqux"
	res, modified := redactString(re, s)
	assert.Equal(t, REDACTION_STR+"qux", res)
	assert.True(t, modified)

	s = "innocent"
	res, modified = redactString(re, s)
	assert.Equal(t, "innocent", res)
	assert.False(t, modified)
}

func TestRedact_Simple(t *testing.T) {
	args := "--verbose=true --password ybx511!ackt544 --username foobar"

	filterList := `{"redact": ["(?:--password|-p)[\\s=]+(\\S+)"]}`
	filters, err := ParseRedactionFilterList(filterList)
	require.NoError(t, err)

	redacted, _ := filters.Redact("", args, []string{""})
	assert.Equal(t, "--verbose=true --password "+REDACTION_STR+" --username foobar", redacted)
}

func TestRedact_BinaryFilter(t *testing.T) {
	args := "--verbose=true --password ybx511!ackt544 --username foobar"

	filterList := `{"binary_regex": ["mysql$"], "redact": ["(?:--password|-p)[\\s=]+(\\S+)"]}`
	filters, err := ParseRedactionFilterList(filterList)
	require.NoError(t, err)

	redacted, _ := filters.Redact("", args, []string{""})
	assert.Equal(t, args, redacted, "redaction without binary match")

	redacted, _ = filters.Redact("/bin/mysql", args, []string{""})
	assert.Equal(t, "--verbose=true --password "+REDACTION_STR+" --username foobar", redacted, "redaction with binary match")
}

func TestRedact_Multi(t *testing.T) {
	args := "--verbose=true --password ybx511!ackt544 --username foobar cheesecake TOPSECRET innocent"

	filterList := `{"redact": ["(?:--password|-p)[\\s=]+(\\S+)", "\\W(TOPSECRET)\\W", "(cheese)cake"]}`
	filters, err := ParseRedactionFilterList(filterList)
	require.NoError(t, err)

	redacted, _ := filters.Redact("", args, []string{""})
	assert.Equal(t, "--verbose=true --password "+REDACTION_STR+" --username foobar "+REDACTION_STR+"cake "+REDACTION_STR+" innocent", redacted)
}

func TestRedact_Envs(t *testing.T) {
	envs := []string{
		"VAR1=XXX",
		"SSH_PASSWORD=verysecretpassword",
		"VAR2=YYY",
	}

	filterList := `{"redact": ["(?:SSH_PASSWORD)[\\s=]+(\\S+)"]}`
	filters, err := ParseRedactionFilterList(filterList)
	require.NoError(t, err)

	_, redacted := filters.Redact("", "", envs)

	str := strings.Join(redacted, " ")
	assert.Equal(t, "VAR1=XXX SSH_PASSWORD="+REDACTION_STR+" VAR2=YYY", str)
}

func TestRedact_ArgsWithEnvs(t *testing.T) {
	args := "--verbose=true --password ybx511!ackt544 --username foobar cheesecake TOPSECRET innocent"
	envs := []string{
		"VAR1=XXX",
		"SSH_PASSWORD=verysecretpassword",
		"VAR2=YYY",
	}

	filterList := `{"redact": ["(?:--password|-p)[\\s=]+(\\S+)", "\\W(TOPSECRET)\\W", "(cheese)cake", "(?:SSH_PASSWORD)[\\s=]+(\\S+)"]}`
	filters, err := ParseRedactionFilterList(filterList)
	require.NoError(t, err)

	args, envs = filters.Redact("", args, envs)
	assert.Equal(t, "--verbose=true --password "+REDACTION_STR+" --username foobar "+REDACTION_STR+"cake "+REDACTION_STR+" innocent", args)

	str := strings.Join(envs, " ")
	assert.Equal(t, "VAR1=XXX SSH_PASSWORD="+REDACTION_STR+" VAR2=YYY", str)
}
