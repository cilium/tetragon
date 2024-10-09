// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package bugtool

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFindPinnedMaps(t *testing.T) {
	t.Run("NoSuchFile", func(t *testing.T) {
		const path = "/sys/fs/bpf/nosuchfile"
		_, err := FindPinnedMaps(path)
		assert.Error(t, err)
		_, err = FindMapsUsedByPinnedProgs(path)
		assert.Error(t, err)
	})
}
