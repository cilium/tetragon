// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package path

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_getBinaryAbsolutePath(t *testing.T) {
	assert.Equal(t, "C:\\usr\\bin\\cat", GetBinaryAbsolutePath("C:\\usr\\bin\\cat", "/tmp"))
	assert.Equal(t, "C:\\usr\\bin\\cat", GetBinaryAbsolutePath(".\\bin\\cat", "C:\\usr"))
	assert.Equal(t, "C:\\usr\\bin\\cat", GetBinaryAbsolutePath("..\\usr\\bin\\cat", "C:\\etc"))
	assert.Equal(t, "C:\\usr\\bin\\cat", GetBinaryAbsolutePath("..\\..\\bin\\cat", "C:\\usr\\local\\bin"))
}
