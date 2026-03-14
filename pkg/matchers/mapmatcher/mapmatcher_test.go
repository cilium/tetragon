// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package mapmatcher

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

type mockMatcher struct {
	expected string
}

func (m mockMatcher) Match(actual string) error {
	if m.expected != actual {
		return assert.AnError
	}
	return nil
}

func TestMapMatcher(t *testing.T) {
	m := MapMatcher[string, string, mockMatcher]{
		"key1": mockMatcher{"val1"},
		"key2": mockMatcher{"val2"},
	}

	// Successful match
	actual := map[string]string{
		"key1": "val1",
		"key2": "val2",
	}
	require.NoError(t, m.Match(actual))

	// Unmatched key in actual (allowed, we only check what's in the matcher)
	actualExtra := map[string]string{
		"key1": "val1",
		"key2": "val2",
		"key3": "val3",
	}
	require.NoError(t, m.Match(actualExtra))

	// Missing key in actual
	actualMissing := map[string]string{
		"key1": "val1",
	}
	require.Error(t, m.Match(actualMissing))

	// Value mismatch
	actualMismatch := map[string]string{
		"key1": "val1",
		"key2": "wrong",
	}
	require.Error(t, m.Match(actualMismatch))
}

func TestPrimitiveMatcher(t *testing.T) {
	// Int32
	mInt := PrimitiveMatcher[int32]{Value: 42}
	require.NoError(t, mInt.Match(42))
	require.Error(t, mInt.Match(43))

	// Bool
	mBool := PrimitiveMatcher[bool]{Value: true}
	require.NoError(t, mBool.Match(true))
	require.Error(t, mBool.Match(false))

	// YAML unmarshaling
	var mUnsh PrimitiveMatcher[int32]
	err := yaml.Unmarshal([]byte("42"), &mUnsh)
	require.NoError(t, err)
	assert.Equal(t, int32(42), mUnsh.Value)
}
