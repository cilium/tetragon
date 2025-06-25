// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package aggregator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_getNameOrIp(t *testing.T) {
	assert.Equal(t, "1.1.1.1", getNameOrIP("1.1.1.1", []string{}))
	assert.Equal(t, "a.com,b.com,c.com", getNameOrIP("1.1.1.1", []string{"b.com", "c.com", "a.com"}))
}
