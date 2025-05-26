// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package bytesmatcher

import (
	"encoding/base64"
	"testing"

	"github.com/cilium/tetragon/pkg/eventcheckertests/yamlhelpers"
	"github.com/stretchr/testify/require"
)

func TestBytesMatcherFullSmoke(t *testing.T) {
	bytes := []byte{'F', 'O', 'O', 137, 0, '\n'}

	enc := base64.StdEncoding.EncodeToString(bytes)

	yamlStr := `
    operator: full
    value: "` + enc + `"
    `

	var checker BytesMatcher
	if !yamlhelpers.AssertUnmarshalRoundTrip(t, []byte(yamlStr), &checker) {
		t.FailNow()
	}

	err := checker.Match(bytes)
	require.NoError(t, err)

	err = checker.Match(bytes[:3])
	require.Error(t, err)
}

func TestBytesMatcherPrefixSmoke(t *testing.T) {
	bytes := []byte{'F', 'O', 'O', 137, 0, '\n'}

	enc := base64.StdEncoding.EncodeToString(bytes[:3])

	yamlStr := `
    operator: prefix
    value: "` + enc + `"
    `

	var checker BytesMatcher
	if !yamlhelpers.AssertUnmarshalRoundTrip(t, []byte(yamlStr), &checker) {
		t.FailNow()
	}

	err := checker.Match(bytes)
	require.NoError(t, err)

	err = checker.Match(bytes[:3])
	require.NoError(t, err)

	err = checker.Match(bytes[:2])
	require.Error(t, err)
}

func TestBytesMatcherSuffixSmoke(t *testing.T) {
	bytes := []byte{'F', 'O', 'O', 137, 0, '\n'}

	enc := base64.StdEncoding.EncodeToString(bytes[3:])

	yamlStr := `
    operator: suffix
    value: "` + enc + `"
    `

	var checker BytesMatcher
	if !yamlhelpers.AssertUnmarshalRoundTrip(t, []byte(yamlStr), &checker) {
		t.FailNow()
	}

	err := checker.Match(bytes)
	require.NoError(t, err)

	err = checker.Match(bytes[3:])
	require.NoError(t, err)

	err = checker.Match(bytes[:3])
	require.Error(t, err)
}

func TestBytesMatcherContainsSmoke(t *testing.T) {
	bytes := []byte{'F', 'O', 'O', 137, 0, '\n'}

	enc := base64.StdEncoding.EncodeToString(bytes[2:4])

	yamlStr := `
    operator: contains
    value: "` + enc + `"
    `

	var checker BytesMatcher
	if !yamlhelpers.AssertUnmarshalRoundTrip(t, []byte(yamlStr), &checker) {
		t.FailNow()
	}

	err := checker.Match(bytes)
	require.NoError(t, err)

	err = checker.Match(bytes[:4])
	require.NoError(t, err)

	err = checker.Match(bytes[1:4])
	require.NoError(t, err)

	err = checker.Match(bytes[:3])
	require.Error(t, err)
}
