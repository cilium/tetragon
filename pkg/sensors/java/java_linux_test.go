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

func TestHasAgentMapping(t *testing.T) {
	require.True(t, hasAgentMapping([]byte(
		"7f2a54000000-7f2a54021000 rw-p 00000000 00:00 0\n"+
			"7f2a5c1f9000-7f2a5c1fd000 r-xp 00002000 00:2a 53 "+
			"/tmp/.tetragon-jvmti-4242-7246316.so (deleted)\n")))
	require.False(t, hasAgentMapping([]byte(
		"7f2a5c1f9000-7f2a5c1fd000 r-xp 00002000 fd:01 53 "+
			"/usr/lib/jvm/java-21/lib/server/libjvm.so\n")))
	require.False(t, hasAgentMapping(nil))
}
