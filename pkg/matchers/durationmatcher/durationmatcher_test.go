// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package durationmatcher

import (
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/eventcheckertests/yamlhelpers"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestDurationMatcherFullSmoke(t *testing.T) {
	yamlStr := `
    operator: full
    value: 2s
    `

	var checker DurationMatcher
	if !yamlhelpers.AssertUnmarshalRoundTrip(t, []byte(yamlStr), &checker) {
		t.FailNow()
	}

	// Exact match
	toCheck := 2 * time.Second
	err := checker.Match(durationpb.New(toCheck))
	assert.NoError(t, err)

	// Bad match
	toCheck = 2 * time.Minute
	err = checker.Match(durationpb.New(toCheck))
	assert.Error(t, err)

	// Make sure a flat duration is the same as a full matcher
	yamlStr2 := `2s`

	var checker2 DurationMatcher
	if !yamlhelpers.AssertUnmarshalRoundTrip(t, []byte(yamlStr2), &checker2) {
		t.FailNow()
	}

	assert.Equal(t, checker, checker2)
}

func TestDurationMatcherLessSmoke(t *testing.T) {
	yamlStr := `
    operator: less
    value: 1m30s
    `

	var checker DurationMatcher
	if !yamlhelpers.AssertUnmarshalRoundTrip(t, []byte(yamlStr), &checker) {
		t.FailNow()
	}

	// Exact match
	toCheck := 1*time.Minute + 30*time.Second
	err := checker.Match(durationpb.New(toCheck))
	assert.NoError(t, err)

	// 1 second less
	toCheck = 1*time.Minute + 29*time.Second
	err = checker.Match(durationpb.New(toCheck))
	assert.NoError(t, err)

	// 1 minute less
	toCheck = 30 * time.Second
	err = checker.Match(durationpb.New(toCheck))
	assert.NoError(t, err)

	// 1 second over
	toCheck = 1*time.Minute + 31*time.Second
	err = checker.Match(durationpb.New(toCheck))
	assert.Error(t, err)

	// 1 minute over
	toCheck = 2*time.Minute + 30*time.Second
	err = checker.Match(durationpb.New(toCheck))
	assert.Error(t, err)
}

func TestDurationMatcherGreaterSmoke(t *testing.T) {
	yamlStr := `
    operator: greater
    value: 1m30s
    `

	var checker DurationMatcher
	if !yamlhelpers.AssertUnmarshalRoundTrip(t, []byte(yamlStr), &checker) {
		t.FailNow()
	}

	// Exact match
	toCheck := 1*time.Minute + 30*time.Second
	err := checker.Match(durationpb.New(toCheck))
	assert.NoError(t, err)

	// 1 second greater
	toCheck = 1*time.Minute + 31*time.Second
	err = checker.Match(durationpb.New(toCheck))
	assert.NoError(t, err)

	// 1 minute greater
	toCheck = 2*time.Minute + 30*time.Second
	err = checker.Match(durationpb.New(toCheck))
	assert.NoError(t, err)

	// 1 second under
	toCheck = 1*time.Minute + 29*time.Second
	err = checker.Match(durationpb.New(toCheck))
	assert.Error(t, err)

	// 1 minute under
	toCheck = 30 * time.Second
	err = checker.Match(durationpb.New(toCheck))
	assert.Error(t, err)
}

func TestDurationMatcherBetweenSmoke(t *testing.T) {
	yamlStr := `
    operator: between
    value:
        lower: 1m
        upper: 2m
    `

	var checker DurationMatcher
	if !yamlhelpers.AssertUnmarshalRoundTrip(t, []byte(yamlStr), &checker) {
		t.FailNow()
	}

	// Exact match on lower bound
	toCheck := 1 * time.Minute
	err := checker.Match(durationpb.New(toCheck))
	assert.NoError(t, err)

	// Exact match on upper bound
	toCheck = 2 * time.Minute
	err = checker.Match(durationpb.New(toCheck))
	assert.NoError(t, err)

	// In between
	toCheck = 1*time.Minute + 30*time.Second
	err = checker.Match(durationpb.New(toCheck))
	assert.NoError(t, err)

	// Under
	toCheck = 59 * time.Second
	err = checker.Match(durationpb.New(toCheck))
	assert.Error(t, err)

	// Over
	toCheck = 2*time.Minute + 1*time.Second
	err = checker.Match(durationpb.New(toCheck))
	assert.Error(t, err)
}
