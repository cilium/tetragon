// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package node

import "os"

// getNodeNameForExport returns node name string for JSON export. It uses NODE_NAME
// env variable by default, which is also used by k8s watcher to watch for local pods:
//
//	https://github.com/cilium/tetragon/blob/a7be620c9fecdc2b693e3633506aca35d46cd3b2/pkg/grpc/watcher.go#L32
//
// Set HUBBLE_NODE_NAME to override the node_name field for JSON export.
func GetNodeNameForExport() string {
	nodeName := os.Getenv("HUBBLE_NODE_NAME")
	if nodeName != "" {
		return nodeName
	}
	return os.Getenv("NODE_NAME")
}
