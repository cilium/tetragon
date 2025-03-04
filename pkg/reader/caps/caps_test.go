// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package caps

import (
	"testing"

	"github.com/cilium/tetragon/pkg/constants"
	"github.com/stretchr/testify/assert"
)

func TestIsCapValid(t *testing.T) {
	valid := isCapValid(constants.CAP_CHOWN)
	assert.Equal(t, true, valid)

	valid = isCapValid(constants.CAP_CHOWN - 1)
	assert.Equal(t, false, valid)

	valid = isCapValid(constants.CAP_LAST_CAP)
	assert.Equal(t, true, valid)

	valid = isCapValid(constants.CAP_LAST_CAP + 1)
	assert.Equal(t, false, valid)
}

func TestGetCapability(t *testing.T) {
	// Test our caps package if it was updated and contains the last CAP_LAST_CAP from upstream
	str, err := GetCapability(constants.CAP_LAST_CAP)
	assert.NoError(t, err)
	assert.NotEmpty(t, str)

	str, err = GetCapability(constants.CAP_CHOWN)
	assert.NoError(t, err)
	assert.Equal(t, "CAP_CHOWN", str)

	str, err = GetCapability(constants.CAP_LAST_CAP + 1)
	assert.Error(t, err)
	assert.Empty(t, str)

	str, err = GetCapability(constants.CAP_CHOWN - 1)
	assert.Error(t, err)
	assert.Empty(t, str)
}

func TestCapsAreSubset(t *testing.T) {
	assert.Equal(t, true, AreSubset(0x000001ffffffffff, 0x000001ffffffffff))
	assert.Equal(t, true, AreSubset(0x000001fffffffffe, 0x000001ffffffffff))
	assert.Equal(t, false, AreSubset(0x000001ffffffffff, 0x000001fffffffffe))
	assert.Equal(t, true, AreSubset(0x0, 0x0))
}
