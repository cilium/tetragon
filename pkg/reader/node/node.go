// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package node

import (
	"os"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
)

const (
	hubbleNodeNameEnvVar = "HUBBLE_NODE_NAME"
	nodeNameEnvVar       = "NODE_NAME"
)

var (
	kubernetesNodeName string
	exportNodeName     string
)

func init() {
	SetExportNodeName()
	SetKubernetesNodeName()
}

// SetExportNodeName initializes the exportNodeName variable. It's defined separately from
// init() so that it can be called from unit tests.
func SetExportNodeName() {
	var err error
	if exportNodeName = os.Getenv(hubbleNodeNameEnvVar); exportNodeName != "" {
		return
	}
	if exportNodeName = os.Getenv(nodeNameEnvVar); exportNodeName != "" {
		return
	}
	exportNodeName, err = os.Hostname()
	if err != nil {
		logger.GetLogger().WithError(err).Warn("failed to retrieve hostname")
	}
}

// SetKubernetesNodeName initializes the kubernetesNodeName variable. It's defined separately from
// init() so that it can be called from unit tests.
func SetKubernetesNodeName() {
	var err error
	if kubernetesNodeName = os.Getenv(nodeNameEnvVar); kubernetesNodeName != "" {
		return
	}
	if kubernetesNodeName = os.Getenv(hubbleNodeNameEnvVar); kubernetesNodeName != "" {
		return
	}
	kubernetesNodeName, err = os.Hostname()
	if err != nil {
		logger.GetLogger().WithError(err).Warn("failed to retrieve hostname")
	}
}

// GetNodeNameForExport returns node name string for JSON export. It uses the HUBBLE_NODE_NAME
// env variable by default, and falls back to NODE_NAME if the former is missing. If both
// are missing, it will use the host name reported by the kernel
func GetNodeNameForExport() string {
	return exportNodeName
}

// GetKubernetesNodeName returns node name string for the given node in Kubernetes. It uses the NODE_NAME
// env variable by default, and falls back to HUBBLE_NODE_NAME if the former is missing. If both
// are missing, it will use the host name reported by the kernel. This value is used when watching for
// pods running on the node in Kubernetes.
//
// NOTE: This is different from the Export equivalent for cases where nodes in kubernetes are named different
// from the desired node name in the JSON export.
func GetKubernetesNodeName() string {
	return kubernetesNodeName
}

// SetCommonFields set fields that are common in all the events.
func SetCommonFields(ev *tetragon.GetEventsResponse) {
	ev.NodeName = exportNodeName
	ev.ClusterName = option.Config.ClusterName
}
