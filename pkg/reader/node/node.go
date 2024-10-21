// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package node

import (
	"os"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
)

var (
	nodeName string
)

func init() {
	SetNodeName()
}

// SetNodeName initializes the nodeName variable. It's defined separately from
// init() so that it can be called from unit tests.
func SetNodeName() {
	var err error
	nodeName = os.Getenv("HUBBLE_NODE_NAME")
	if nodeName == "" {
		nodeName = os.Getenv("NODE_NAME")
	}
	if nodeName == "" {
		nodeName, err = os.Hostname()
		if err != nil {
			logger.GetLogger().WithError(err).Warn("failed to retrieve hostname")
		}
	}
}

// GetNodeNameForExport returns node name string for JSON export. It uses NODE_NAME
// env variable by default, which is also used by k8s watcher to watch for local pods:
//
//	https://github.com/cilium/tetragon/blob/a7be620c9fecdc2b693e3633506aca35d46cd3b2/pkg/grpc/watcher.go#L32
//
// Set HUBBLE_NODE_NAME to override the node_name field for JSON export.
func GetNodeNameForExport() string {
	return nodeName
}

// SetCommonFields set fields that are common in all the events.
func SetCommonFields(ev *tetragon.GetEventsResponse) {
	ev.NodeName = nodeName
	ev.ClusterName = option.Config.ClusterName
}
