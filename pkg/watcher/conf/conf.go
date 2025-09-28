// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package conf

import (
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/cilium/tetragon/pkg/option"
)

// K8sConfig alias is mainly for testing and extension if required.
var K8sConfig = k8sConfig

// K8sConfigRetry alias is for clients to override the retry default, if required
var K8sConfigRetry = k8sConfigRetry

// K8sConfig returns Kubernetes client configuration. If running in-cluster, the
// second return value is true, otherwise false.
func k8sConfig() (*rest.Config, bool, error) {
	if option.Config.K8sKubeConfigPath != "" {
		cfg, err := clientcmd.BuildConfigFromFlags("", option.Config.K8sKubeConfigPath)
		return cfg, false, err
	}
	cfg, err := rest.InClusterConfig()
	return cfg, true, err
}

// k8sConfigRetry returns the number of attempts configured for the Kubernetes control plane.
// It retrieves this value from the global option.Config.K8sControlPlaneRetry setting.
// Negative values indicate infinite retries, zero is invalid, and positive values specify the maximum number of attempts.
// Default behavior is 1 attempt.
func k8sConfigRetry() (retryAttempts int) {
	return option.Config.K8sControlPlaneRetry
}
