// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package v1alpha1

import (
	ciliumio "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// PodInfo (PI) is the custom resource that stores pod related information

	// PIPluralName is the plural name of Tetragon Pod Info
	PIPluralName = "podinfo"

	// PIKindDefinition is the Kind name of the Tetragon Pod Info
	PIKindDefinition = "PodInfo"

	// PIName is the full name of the Tetragon Pod Info
	PIName = PIPluralName + "." + ciliumio.GroupName
)

type PodInfoSpec struct {

	// Host networking requested for this pod. Use the host's network namespace.
	// If this option is set, the ports that will be used must be specified.
	HostNetwork bool `json:"hostNetwork,omitempty"`
}

type PodInfoStatus struct {
	// IP address allocated to the pod. Routable at least within the cluster.
	// Empty if not yet allocated.
	PodIP string `json:"podIP,omitempty"`

	// List of Ip addresses allocated to the pod. 0th entry must be same as PodIP.
	PodIPs []PodIP `json:"podIPs,omitempty"`
}

type PodIP struct {
	// IP is an IP address (IPv4 or IPv6) assigned to the pod
	IP string `json:"IP,omitempty"`
}

//+kubebuilder:object:root=true

// PodInfo is the Scheme for the Podinfo API
type PodInfo struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PodInfoSpec   `json:"spec,omitempty"`
	Status PodInfoStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true
// +kubebuilder:subresource:status

// PodInfoList contains a list of Podinfo
type PodInfoList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PodInfo `json:"items"`
}
