// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"os"
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/stretchr/testify/assert"
)

func TestGetNodeNameForExport(t *testing.T) {
	assert.NotEqual(t, "", GetNodeNameForExport()) // we should get the hostname here
	assert.NoError(t, os.Setenv("NODE_NAME", "from-node-name"))
	SetNodeName()
	assert.Equal(t, "from-node-name", GetNodeNameForExport())
	assert.NoError(t, os.Setenv("HUBBLE_NODE_NAME", "from-hubble-node-name"))
	SetNodeName()
	assert.Equal(t, "from-hubble-node-name", GetNodeNameForExport())
	assert.NoError(t, os.Unsetenv("NODE_NAME"))
	assert.NoError(t, os.Unsetenv("HUBBLE_NODE_NAME"))
}

func TestSetCommonFields(t *testing.T) {
	ev := tetragon.GetEventsResponse{}
	assert.Empty(t, ev.NodeName)
	nodeName := "my-node-name"
	assert.NoError(t, os.Setenv("NODE_NAME", nodeName))
	SetNodeName()
	SetCommonFields(&ev)
	assert.Equal(t, nodeName, ev.GetNodeName())
	assert.NoError(t, os.Unsetenv("NODE_NAME"))
}
