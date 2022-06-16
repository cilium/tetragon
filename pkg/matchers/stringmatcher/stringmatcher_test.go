// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package stringmatcher

import (
	"testing"

	"github.com/cilium/tetragon/pkg/eventcheckertests/yamlhelpers"
	"github.com/stretchr/testify/assert"
)

func TestStringMatcherFullSmoke(t *testing.T) {
	str := "foobarqux"

	yamlStr := `
    operator: full
    value: "` + str + `"
    `

	var checker StringMatcher
	if !yamlhelpers.AssertUnmarshalRoundTrip(t, []byte(yamlStr), &checker) {
		t.FailNow()
	}

	err := checker.Match(str)
	assert.NoError(t, err)

	err = checker.Match(str[:3])
	assert.Error(t, err)
}

func TestStringMatcherPrefixSmoke(t *testing.T) {
	str := "foobarqux"

	yamlStr := `
    operator: prefix
    value: "` + str[:3] + `"
    `

	var checker StringMatcher
	if !yamlhelpers.AssertUnmarshalRoundTrip(t, []byte(yamlStr), &checker) {
		t.FailNow()
	}

	err := checker.Match(str)
	assert.NoError(t, err)

	err = checker.Match(str[:3])
	assert.NoError(t, err)

	err = checker.Match(str[2:])
	assert.Error(t, err)
}

func TestStringMatcherSuffixSmoke(t *testing.T) {
	str := "foobarqux"

	yamlStr := `
    operator: suffix
    value: "` + str[3:] + `"
    `

	var checker StringMatcher
	if !yamlhelpers.AssertUnmarshalRoundTrip(t, []byte(yamlStr), &checker) {
		t.FailNow()
	}

	err := checker.Match(str)
	assert.NoError(t, err)

	err = checker.Match(str[3:])
	assert.NoError(t, err)

	err = checker.Match(str[:3])
	assert.Error(t, err)
}

func TestStringMatcherContainsSmoke(t *testing.T) {
	str := "foobarqux"

	yamlStr := `
    operator: contains
    value: "` + str[1:4] + `"
    `

	var checker StringMatcher
	if !yamlhelpers.AssertUnmarshalRoundTrip(t, []byte(yamlStr), &checker) {
		t.FailNow()
	}

	err := checker.Match(str)
	assert.NoError(t, err)

	err = checker.Match(str[:4])
	assert.NoError(t, err)

	err = checker.Match(str[1:4])
	assert.NoError(t, err)

	err = checker.Match(str[:3])
	assert.Error(t, err)
}

func TestStringMatcherRegexSmoke(t *testing.T) {
	yamlStr := `
    operator: regex
    value: ".*barqux$"
    `

	var checker StringMatcher
	if !yamlhelpers.AssertUnmarshalRoundTrip(t, []byte(yamlStr), &checker) {
		t.FailNow()
	}

	err := checker.Match("foobarqux")
	assert.NoError(t, err)

	err = checker.Match("barqux")
	assert.NoError(t, err)

	err = checker.Match("bazbarqux")
	assert.NoError(t, err)

	err = checker.Match("foobarqu")
	assert.Error(t, err)

	err = checker.Match("foobarquxxxxx")
	assert.Error(t, err)
}
