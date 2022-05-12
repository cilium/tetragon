// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package proc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetProcStatStrings(t *testing.T) {
	stat := "206305 (zsh( )foo) S 206303 206305 206305 34821 206368 4194304 9687 4455 0 0 56 17 2 0 20 0 1 0 19321046 17514496 1866 18446744073709551615 94273300672512 94273301280581 140729040978832 0 0 0 2 3686400 134295555 1 0 0 17 3 0 0 0 0 0 94273301428976 94273301458280 94273325256704 140729040984354 140729040984358 140729040984358 140729040986095 0"
	statStrings := getProcStatStrings(stat)
	assert.Equal(t, statStrings[0], "206305", "Incorrect first field")
	assert.Equal(t, statStrings[1], "(zsh( )foo)", "Incorrect comm field")
	assert.Equal(t, statStrings[2], "S", "Incorrect third field")
	assert.Equal(t, statStrings[3], "206303", "Incorrect fourth field")
	assert.Equal(t, statStrings[50], "140729040986095", "Incorrect 51st field")
	assert.Equal(t, statStrings[51], "0", "Incorrect 52nd field")
	assert.Equal(t, len(statStrings), 52, "Incorrect number of entries")
}
