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

// PodInfoSpec defines the desired state of PodInfo. It contains the pod IP and metadata that will be populated by the operator.
type PodInfoSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	// PodName is the IP address of the pod
	PodIP string `json:"podIP"`
	// PodName contains the additional details like name, version, labels etc.
	PodMetadata string `json:"podMetadata"`
}

//+kubebuilder:object:root=true

// PodInfo is the Schema for the podinfoes API
type PodInfo struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec PodInfoSpec `json:"spec,omitempty"`
}

//+kubebuilder:object:root=true

// PodInfoList contains a list of PodInfo
type PodInfoList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []PodInfo `json:"items"`
}

func init() {
	SchemeBuilder.Register(&PodInfo{}, &PodInfoList{})
}
