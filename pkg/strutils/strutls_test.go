// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package strutils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

type parseSize struct {
	str string
	err bool
	val int
}

func TestParseSize(t *testing.T) {
	var tests = []parseSize{
		parseSize{"1K", false, 1024},
		parseSize{"256M", false, 256 * 1024 * 1024},
		parseSize{"10G", false, 10 * 1024 * 1024 * 1024},
		parseSize{"10k", true, 0},
		parseSize{"abc", true, 0},
		parseSize{"abcM", true, 0},
	}

	for idx := range tests {
		test := tests[idx]
		val, err := ParseSize(test.str)
		assert.Equal(t, val, test.val)
		assert.Equal(t, err != nil, test.err)
	}
}
