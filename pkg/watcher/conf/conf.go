// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package conf

import (
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/cilium/tetragon/pkg/option"
)

// K8sConfig returns Kubernetes client configuration. If running in-cluster, the
// second return value is true, otherwise false.
func K8sConfig() (*rest.Config, bool, error) {
	if option.Config.K8sKubeConfigPath != "" {
		cfg, err := clientcmd.BuildConfigFromFlags("", option.Config.K8sKubeConfigPath)
		return cfg, false, err
	}
	cfg, err := rest.InClusterConfig()
	return cfg, true, err
}
