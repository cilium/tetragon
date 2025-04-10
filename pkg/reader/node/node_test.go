// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"os"
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/stretchr/testify/assert"
)

func TestGetNodeNameForExport(t *testing.T) {
	assert.NotEqual(t, "", GetNodeNameForExport()) // we should get the hostname here
	assert.NoError(t, os.Setenv("NODE_NAME", "from-node-name"))
	SetExportNodeName()
	assert.Equal(t, "from-node-name", GetNodeNameForExport())
	assert.NoError(t, os.Setenv("HUBBLE_NODE_NAME", "from-hubble-node-name"))
	SetExportNodeName()
	assert.Equal(t, "from-hubble-node-name", GetNodeNameForExport())
	assert.NoError(t, os.Unsetenv("NODE_NAME"))
	assert.NoError(t, os.Unsetenv("HUBBLE_NODE_NAME"))
}

func TestSetCommonFields(t *testing.T) {
	ev := tetragon.GetEventsResponse{}
	assert.Empty(t, ev.NodeName)
	assert.Empty(t, ev.ClusterName)
	nodeName := "my-node-name"
	assert.NoError(t, os.Setenv("NODE_NAME", nodeName))
	SetExportNodeName()
	option.Config.ClusterName = "my-cluster-name"
	SetCommonFields(&ev)
	assert.Equal(t, nodeName, ev.GetNodeName())
	assert.Equal(t, option.Config.ClusterName, ev.GetClusterName())
	assert.NoError(t, os.Unsetenv("NODE_NAME"))
}

func TestGetKubernetesNodeName(t *testing.T) {
	assert.NotEqual(t, "", GetKubernetesNodeName()) // we should get the hostname here
	assert.NoError(t, os.Setenv("NODE_NAME", "from-node-name"))
	SetKubernetesNodeName()
	assert.Equal(t, "from-node-name", GetKubernetesNodeName())
	assert.NoError(t, os.Setenv("HUBBLE_NODE_NAME", "from-hubble-node-name"))
	SetKubernetesNodeName()
	assert.Equal(t, "from-node-name", GetKubernetesNodeName())
	assert.NoError(t, os.Unsetenv("NODE_NAME"))
	assert.NoError(t, os.Unsetenv("HUBBLE_NODE_NAME"))
}
