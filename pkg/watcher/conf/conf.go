// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package conf

import (
	"github.com/cilium/tetragon/pkg/option"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func K8sConfig() (*rest.Config, error) {
	if option.Config.K8sKubeConfigPath != "" {
		return clientcmd.BuildConfigFromFlags("", option.Config.K8sKubeConfigPath)
	}
	return rest.InClusterConfig()
}
