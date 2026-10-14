// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package java

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestContainsArgs(t *testing.T) {
	cmdline := []byte("java\x00-orders-service.jar\x00--port=8080\x00")
	require.True(t, containsArgs(cmdline, []string{"orders", "port=8080"}))
	require.False(t, containsArgs(cmdline, []string{"orders", "missing"}))
	require.True(t, containsArgs(cmdline, nil))
}
