// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Copyright Istio Authors
// Part of this file was copied from
// https://github.com/istio/istio/blob/483f3466eca1de70164dd3af33fb411d9e311c23/pkg/kube/util.go

package podhelpers

import (
	"regexp"
	"strings"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var cronJobNameRegexp = regexp.MustCompile(`(.+)-\d{8,10}$`)

func GetTopLevelWorkloadFromPod(pod *corev1.Pod) v1alpha1.TopLevelWorkload {
	o, t := GetTopLevelWorkloadMetaFromPod(pod)
	return v1alpha1.TopLevelWorkload{
		TypeMeta:  t,
		Name:      o.Name,
		Namespace: o.Namespace,
	}
}

// GetTopLevelWorkloadFromPod heuristically derives workload metadata from the Pod spec.
func GetTopLevelWorkloadMetaFromPod(pod *corev1.Pod) (metav1.ObjectMeta, metav1.TypeMeta) {
	if pod == nil {
		return metav1.ObjectMeta{}, metav1.TypeMeta{}
	}
	// try to capture more useful namespace/name info for deployments, etc.
	// TODO(dougreid): expand to enable lookup of OWNERs recursively a la kubernetesenv
	deployMeta := metav1.ObjectMeta{
		Name:      pod.Name,
		Namespace: pod.Namespace,
	}

	typeMetadata := metav1.TypeMeta{
		Kind:       "Pod",
		APIVersion: "v1",
	}
	if len(pod.GenerateName) > 0 {
		// if the pod name was generated (or is scheduled for generation), we can begin an investigation into the controlling reference for the pod.
		var controllerRef metav1.OwnerReference
		controllerFound := false
		for _, ref := range pod.GetOwnerReferences() {
			if ref.Controller != nil && *ref.Controller {
				controllerRef = ref
				controllerFound = true
				break
			}
		}
		if controllerFound {
			typeMetadata.APIVersion = controllerRef.APIVersion
			typeMetadata.Kind = controllerRef.Kind

			// heuristic for deployment detection
			deployMeta.Name = controllerRef.Name
			if typeMetadata.Kind == "ReplicaSet" && pod.Labels["pod-template-hash"] != "" && strings.HasSuffix(controllerRef.Name, pod.Labels["pod-template-hash"]) {
				name := strings.TrimSuffix(controllerRef.Name, "-"+pod.Labels["pod-template-hash"])
				deployMeta.Name = name
				typeMetadata.Kind = "Deployment"
			} else if typeMetadata.Kind == "ReplicationController" && pod.Labels["deploymentconfig"] != "" {
				// If the pod is controlled by the replication controller, which is created by the DeploymentConfig resource in
				// Openshift platform, set the deploy name to the deployment config's name, and the kind to 'DeploymentConfig'.
				//
				// nolint: lll
				// For DeploymentConfig details, refer to
				// https://docs.openshift.com/container-platform/4.1/applications/deployments/what-deployments-are.html#deployments-and-deploymentconfigs_what-deployments-are
				//
				// For the reference to the pod label 'deploymentconfig', refer to
				// https://github.com/openshift/library-go/blob/7a65fdb398e28782ee1650959a5e0419121e97ae/pkg/apps/appsutil/const.go#L25
				deployMeta.Name = pod.Labels["deploymentconfig"]
				typeMetadata.Kind = "DeploymentConfig"
			} else if typeMetadata.Kind == "Job" {
				// If job name suffixed with `-<digit-timestamp>`, where the length of digit timestamp is 8~10,
				// trim the suffix and set kind to cron job.
				if jn := cronJobNameRegexp.FindStringSubmatch(controllerRef.Name); len(jn) == 2 {
					deployMeta.Name = jn[1]
					typeMetadata.Kind = "CronJob"
					// heuristically set cron job api version to v1beta1 as it cannot be derived from pod metadata.
					// Cronjob is not GA yet and latest version is v1beta1: https://github.com/kubernetes/enhancements/pull/978
					typeMetadata.APIVersion = "batch/v1beta1"
				}
			}
		}
	}

	if deployMeta.Name == "" {
		// if we haven't been able to extract a deployment name, then just give it the pod name
		deployMeta.Name = pod.Name
	}

	return deployMeta, typeMetadata
}
