// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package caps

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestIsCapValid(t *testing.T) {
	valid := isCapValid(unix.CAP_CHOWN)
	assert.Equal(t, true, valid)

	valid = isCapValid(unix.CAP_CHOWN - 1)
	assert.Equal(t, false, valid)

	valid = isCapValid(unix.CAP_LAST_CAP)
	assert.Equal(t, true, valid)

	valid = isCapValid(unix.CAP_LAST_CAP + 1)
	assert.Equal(t, false, valid)
}

func TestGetCapability(t *testing.T) {
	// Test our caps package if it was updated and contains the last CAP_LAST_CAP from upstream
	str, err := GetCapability(unix.CAP_LAST_CAP)
	assert.NoError(t, err)
	assert.NotEmpty(t, str)

	str, err = GetCapability(unix.CAP_CHOWN)
	assert.NoError(t, err)
	assert.Equal(t, "CAP_CHOWN", str)

	str, err = GetCapability(unix.CAP_LAST_CAP + 1)
	assert.Error(t, err)
	assert.Empty(t, str)

	str, err = GetCapability(unix.CAP_CHOWN - 1)
	assert.Error(t, err)
	assert.Empty(t, str)
}
