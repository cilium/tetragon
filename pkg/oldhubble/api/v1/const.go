// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package v1

const (
	// ObserverServiceName is the name of the observer service for the grpc health check
	ObserverServiceName = "hubble.server.Observer"

	// K8sNamespaceTag is the label tag which denotes the namespace.
	K8sNamespaceTag = "k8s:io.kubernetes.pod.namespace"
)
