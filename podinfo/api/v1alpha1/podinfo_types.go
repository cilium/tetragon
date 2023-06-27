/*
Copyright 2023 Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

type PodInfoSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

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
	// ip is an IP address (IPv4 or IPv6) assigned to the pod
	IP string `json:"ip,omitempty"`
}

//+kubebuilder:object:root=true

// PodInfo is the Schema for the podinfoes API
type PodInfo struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   PodInfoSpec   `json:"spec,omitempty"`
	Status PodInfoStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true
// +kubebuilder:subresource:status

// PodInfoList contains a list of PodInfo
type PodInfoList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PodInfo `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PodInfo{}, &PodInfoList{})
}
