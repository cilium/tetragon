// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package conf

import (
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/cilium/tetragon/pkg/option"
)

func K8sConfig() (*rest.Config, error) {
	if option.Config.K8sKubeConfigPath != "" {
		return clientcmd.BuildConfigFromFlags("", option.Config.K8sKubeConfigPath)
	}
	return rest.InClusterConfig()
}
