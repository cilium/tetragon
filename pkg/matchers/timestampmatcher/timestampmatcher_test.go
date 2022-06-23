// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package timestampmatcher

import (
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/eventcheckertests/yamlhelpers"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TestTimestampMatcherTimeYaml verifies that several time formats parse to the equivalent
// underlying UTC time.Time in the TimestampMatcher.
func TestTimestampMatcherTimeYaml(t *testing.T) {
	yamlStr1 := `
    operator: day
    value: "2022-05-09T20:29:34Z"
    `

	yamlStr2 := `
    operator: day
    value: "2022-05-09T16:29:34-04:00"
    `

	yamlStr3 := `
    operator: day
    value: "2022-05-09T20:29:34"
    `

	var checker1 TimestampMatcher
	if !yamlhelpers.AssertUnmarshalRoundTrip(t, []byte(yamlStr1), &checker1) {
		t.FailNow()
	}

	var checker2 TimestampMatcher
	if !yamlhelpers.AssertUnmarshalRoundTrip(t, []byte(yamlStr2), &checker2) {
		t.FailNow()
	}

	var checker3 TimestampMatcher
	if !yamlhelpers.AssertUnmarshalRoundTrip(t, []byte(yamlStr3), &checker3) {
		t.FailNow()
	}

	assert.Equal(t, checker1, checker2)
	assert.Equal(t, checker2, checker3)
}

func TestTimestampMatcherDaySmoke(t *testing.T) {
	yamlStr := `
    operator: day
    value: "2022-05-09T20:29:34Z"
    `

	var checker TimestampMatcher
	if !yamlhelpers.AssertUnmarshalRoundTrip(t, []byte(yamlStr), &checker) {
		t.FailNow()
	}

	// Right day, month, year
	toCheck := time.Date(2022, 5, 9, 0, 0, 0, 0, time.UTC)
	err := checker.Match(timestamppb.New(toCheck))
	assert.NoError(t, err)

	// Wrong day
	toCheck = time.Date(2022, 5, 10, 20, 29, 34, 0, time.UTC)
	err = checker.Match(timestamppb.New(toCheck))
	assert.Error(t, err)

	// Wrong month
	toCheck = time.Date(2022, 6, 9, 20, 29, 34, 0, time.UTC)
	err = checker.Match(timestamppb.New(toCheck))
	assert.Error(t, err)

	// Wrong year
	toCheck = time.Date(2023, 5, 9, 20, 29, 34, 0, time.UTC)
	err = checker.Match(timestamppb.New(toCheck))
	assert.Error(t, err)
}

func TestTimestampMatcherHourSmoke(t *testing.T) {
	yamlStr := `
    operator: hour
    value: "2022-05-09T20:29:34Z"
    `

	var checker TimestampMatcher
	if !yamlhelpers.AssertUnmarshalRoundTrip(t, []byte(yamlStr), &checker) {
		t.FailNow()
	}

	// Right day, month, year, hour
	toCheck := time.Date(2022, 5, 9, 20, 0, 0, 0, time.UTC)
	err := checker.Match(timestamppb.New(toCheck))
	assert.NoError(t, err)

	// Wrong hour
	toCheck = time.Date(2022, 5, 9, 21, 29, 34, 0, time.UTC)
	err = checker.Match(timestamppb.New(toCheck))
	assert.Error(t, err)

	// Wrong day
	toCheck = time.Date(2022, 5, 10, 21, 29, 34, 0, time.UTC)
	err = checker.Match(timestamppb.New(toCheck))
	assert.Error(t, err)

	// Wrong month
	toCheck = time.Date(2022, 6, 9, 21, 29, 34, 0, time.UTC)
	err = checker.Match(timestamppb.New(toCheck))
	assert.Error(t, err)

	// Wrong year
	toCheck = time.Date(2023, 5, 9, 21, 29, 34, 0, time.UTC)
	err = checker.Match(timestamppb.New(toCheck))
	assert.Error(t, err)
}

func TestTimestampMatcherMinuteSmoke(t *testing.T) {
	yamlStr := `
    operator: minute
    value: "2022-05-09T20:29:34Z"
    `

	var checker TimestampMatcher
	if !yamlhelpers.AssertUnmarshalRoundTrip(t, []byte(yamlStr), &checker) {
		t.FailNow()
	}

	// Right day, month, year, hour, minute
	toCheck := time.Date(2022, 5, 9, 20, 29, 0, 0, time.UTC)
	err := checker.Match(timestamppb.New(toCheck))
	assert.NoError(t, err)

	// Wrong minute
	toCheck = time.Date(2022, 5, 9, 21, 30, 34, 0, time.UTC)
	err = checker.Match(timestamppb.New(toCheck))
	assert.Error(t, err)

	// Wrong hour
	toCheck = time.Date(2022, 5, 9, 21, 29, 34, 0, time.UTC)
	err = checker.Match(timestamppb.New(toCheck))
	assert.Error(t, err)

	// Wrong day
	toCheck = time.Date(2022, 5, 10, 21, 29, 34, 0, time.UTC)
	err = checker.Match(timestamppb.New(toCheck))
	assert.Error(t, err)

	// Wrong month
	toCheck = time.Date(2022, 6, 9, 21, 29, 34, 0, time.UTC)
	err = checker.Match(timestamppb.New(toCheck))
	assert.Error(t, err)

	// Wrong year
	toCheck = time.Date(2023, 5, 9, 21, 29, 34, 0, time.UTC)
	err = checker.Match(timestamppb.New(toCheck))
	assert.Error(t, err)
}

func TestTimestampMatcherSecondSmoke(t *testing.T) {
	yamlStr := `
    operator: second
    value: "2022-05-09T20:29:34Z"
    `

	var checker TimestampMatcher
	if !yamlhelpers.AssertUnmarshalRoundTrip(t, []byte(yamlStr), &checker) {
		t.FailNow()
	}

	// Right day, month, year, hour, minute, second
	toCheck := time.Date(2022, 5, 9, 20, 29, 34, 0, time.UTC)
	err := checker.Match(timestamppb.New(toCheck))
	assert.NoError(t, err)

	// Wrong second
	toCheck = time.Date(2022, 5, 9, 21, 29, 35, 0, time.UTC)
	err = checker.Match(timestamppb.New(toCheck))
	assert.Error(t, err)

	// Wrong minute
	toCheck = time.Date(2022, 5, 9, 21, 30, 34, 0, time.UTC)
	err = checker.Match(timestamppb.New(toCheck))
	assert.Error(t, err)

	// Wrong hour
	toCheck = time.Date(2022, 5, 9, 21, 29, 34, 0, time.UTC)
	err = checker.Match(timestamppb.New(toCheck))
	assert.Error(t, err)

	// Wrong day
	toCheck = time.Date(2022, 5, 10, 21, 29, 34, 0, time.UTC)
	err = checker.Match(timestamppb.New(toCheck))
	assert.Error(t, err)

	// Wrong month
	toCheck = time.Date(2022, 6, 9, 21, 29, 34, 0, time.UTC)
	err = checker.Match(timestamppb.New(toCheck))
	assert.Error(t, err)

	// Wrong year
	toCheck = time.Date(2023, 5, 9, 21, 29, 34, 0, time.UTC)
	err = checker.Match(timestamppb.New(toCheck))
	assert.Error(t, err)
}

func TestTimestampMatcherBeforeSmoke(t *testing.T) {
	yamlStr := `
    operator: before
    value: "2022-05-09T20:29:34Z"
    `

	var checker TimestampMatcher
	if !yamlhelpers.AssertUnmarshalRoundTrip(t, []byte(yamlStr), &checker) {
		t.FailNow()
	}

	// Equal
	toCheck := time.Date(2022, 5, 9, 20, 29, 34, 0, time.UTC)
	err := checker.Match(timestamppb.New(toCheck))
	assert.NoError(t, err)

	// Second before
	toCheck = time.Date(2022, 5, 9, 20, 29, 33, 0, time.UTC)
	err = checker.Match(timestamppb.New(toCheck))
	assert.NoError(t, err)

	// NS before
	toCheck = time.Date(2022, 5, 9, 20, 29, 33, 137, time.UTC)
	err = checker.Match(timestamppb.New(toCheck))
	assert.NoError(t, err)

	// Year before
	toCheck = time.Date(2021, 5, 9, 20, 29, 34, 0, time.UTC)
	err = checker.Match(timestamppb.New(toCheck))
	assert.NoError(t, err)

	// Second after
	toCheck = time.Date(2022, 5, 9, 20, 29, 35, 0, time.UTC)
	err = checker.Match(timestamppb.New(toCheck))
	assert.Error(t, err)

	// Year after
	toCheck = time.Date(2023, 5, 9, 20, 29, 34, 0, time.UTC)
	err = checker.Match(timestamppb.New(toCheck))
	assert.Error(t, err)

	// NS after
	toCheck = time.Date(2022, 5, 9, 20, 29, 34, 137, time.UTC)
	err = checker.Match(timestamppb.New(toCheck))
	assert.Error(t, err)
}

func TestTimestampMatcherAfterSmoke(t *testing.T) {
	yamlStr := `
    operator: after
    value: "2022-05-09T20:29:34Z"
    `

	var checker TimestampMatcher
	if !yamlhelpers.AssertUnmarshalRoundTrip(t, []byte(yamlStr), &checker) {
		t.FailNow()
	}

	// Equal
	toCheck := time.Date(2022, 5, 9, 20, 29, 34, 0, time.UTC)
	err := checker.Match(timestamppb.New(toCheck))
	assert.NoError(t, err)

	// Second before
	toCheck = time.Date(2022, 5, 9, 20, 29, 33, 0, time.UTC)
	err = checker.Match(timestamppb.New(toCheck))
	assert.Error(t, err)

	// NS before
	toCheck = time.Date(2022, 5, 9, 20, 29, 33, 137, time.UTC)
	err = checker.Match(timestamppb.New(toCheck))
	assert.Error(t, err)

	// Year before
	toCheck = time.Date(2021, 5, 9, 20, 29, 34, 0, time.UTC)
	err = checker.Match(timestamppb.New(toCheck))
	assert.Error(t, err)

	// Second after
	toCheck = time.Date(2022, 5, 9, 20, 29, 35, 0, time.UTC)
	err = checker.Match(timestamppb.New(toCheck))
	assert.NoError(t, err)

	// Year after
	toCheck = time.Date(2023, 5, 9, 20, 29, 34, 0, time.UTC)
	err = checker.Match(timestamppb.New(toCheck))
	assert.NoError(t, err)

	// NS after
	toCheck = time.Date(2022, 5, 9, 20, 29, 34, 137, time.UTC)
	err = checker.Match(timestamppb.New(toCheck))
	assert.NoError(t, err)
}

func TestTimestampMatcherBetweenSmoke(t *testing.T) {
	yamlStr := `
    operator: between
    value:
        after: "2022-05-09T20:29:00Z"
        before: "2022-05-09T20:30:00Z"
    `

	var checker TimestampMatcher
	if !yamlhelpers.AssertUnmarshalRoundTrip(t, []byte(yamlStr), &checker) {
		t.FailNow()
	}

	// Inside
	toCheck := time.Date(2022, 5, 9, 20, 29, 34, 0, time.UTC)
	err := checker.Match(timestamppb.New(toCheck))
	assert.NoError(t, err)

	// Before by 1s
	toCheck = time.Date(2022, 5, 9, 20, 28, 59, 0, time.UTC)
	err = checker.Match(timestamppb.New(toCheck))
	assert.Error(t, err)

	// After by 1s
	toCheck = time.Date(2022, 5, 9, 20, 30, 1, 0, time.UTC)
	err = checker.Match(timestamppb.New(toCheck))
	assert.Error(t, err)
}
