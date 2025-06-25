// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package grpc

import (
	"encoding/base64"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/process"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/cilium/tetragon/pkg/watcher"
)

func TestProcessManagerGetProcessID(t *testing.T) {
	require.NoError(t, os.Setenv("NODE_NAME", "my-node"))
	node.SetExportNodeName()

	err := process.InitCache(watcher.NewFakeK8sWatcher([]interface{}{}), 10, defaults.DefaultProcessCacheGCInterval)
	require.NoError(t, err)
	defer process.FreeCache()
	id := process.GetProcessID(1, 2)
	decoded, err := base64.StdEncoding.DecodeString(id)
	require.NoError(t, err)
	assert.Equal(t, "my-node:2:1", string(decoded))
	require.NoError(t, os.Unsetenv("NODE_NAME"))
}
