// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package path

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_getBinaryAbsolutePath(t *testing.T) {
	assert.Equal(t, "/usr/bin/cat", GetBinaryAbsolutePath("/usr/bin/cat", "/tmp"))
	assert.Equal(t, "/usr/bin/cat", GetBinaryAbsolutePath("./bin/cat", "/usr"))
	assert.Equal(t, "/usr/bin/cat", GetBinaryAbsolutePath("../usr/bin/cat", "/etc"))
	assert.Equal(t, "/usr/bin/cat", GetBinaryAbsolutePath("../../bin/cat", "/usr/local/bin"))
}
