// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package podinfo

import (
	"context"
	"maps"
	"reflect"

	ciliumiov1alpha1 "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/podhelpers"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// Reconciler reconciles a PodInfo object
type Reconciler struct {
	client.Client
	//Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=cilium.io,resources=PodInfo,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=cilium.io,resources=PodInfo/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=cilium.io,resources=PodInfo/finalizers,verbs=update

// Reconcile gets notified about a pod and reconciles the corresponding PodInfo object.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)

	// Get the Pod.
	pod := &corev1.Pod{}
	if err := r.Get(ctx, req.NamespacedName, pod); err != nil {
		if !errors.IsNotFound(err) {
			// Error fetching the pod. Try again later.
			l.Error(err, "unable to fetch Pod")
			return ctrl.Result{}, err
		}
		// Pod is deleted. Nothing to reconcile.
		return ctrl.Result{}, nil
	}
	if pod.GetDeletionTimestamp() != nil {
		// Pod is being deleted. Nothing to reconcile.
		return ctrl.Result{}, nil
	}

	// Wait until the necessary pod fields are available.
	if !hasAllRequiredFields(pod) {
		return ctrl.Result{Requeue: true}, nil
	}

	podInfo := &ciliumiov1alpha1.PodInfo{}
	if err := r.Get(ctx, req.NamespacedName, podInfo); err != nil {
		if !errors.IsNotFound(err) {
			// Error fetching the pod info. Try again later.
			return ctrl.Result{}, err
		}
		// Pod info does not exist. Create it.
		err = r.Create(ctx, generatePodInfo(pod))
		if errors.IsAlreadyExists(err) {
			// Sometimes Create fails with "AlreadyExists" error even though the
			// previous call to Get returned "NotFound" because of a timing issue.
			// Requeue without returning the error when this happens, otherwise
			// the controller logs an error.
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, err
	}
	if !equal(pod, podInfo) {
		updatedPodInfo := generatePodInfo(pod)
		updatedPodInfo.ResourceVersion = podInfo.ResourceVersion
		return ctrl.Result{}, r.Update(ctx, updatedPodInfo)
	}
	return ctrl.Result{}, nil
}

// equal returns true if the given pod and pod info are equal.
func equal(pod *corev1.Pod, podInfo *ciliumiov1alpha1.PodInfo) bool {
	if len(pod.Status.PodIPs) != len(podInfo.Status.PodIPs) {
		return false
	}
	for i, podIP := range pod.Status.PodIPs {
		if podIP.IP != podInfo.Status.PodIPs[i].IP {
			return false
		}
	}

	// check if ownerReference is changed.
	controller := true
	blockOwnerDeletion := true
	expectedOwnerReference := metav1.OwnerReference{
		APIVersion:         "v1",
		Kind:               "Pod",
		Name:               pod.Name,
		UID:                pod.UID,
		Controller:         &controller,
		BlockOwnerDeletion: &blockOwnerDeletion,
	}
	workloadObject, workloadType := podhelpers.GetWorkloadMetaFromPod(pod)
	return pod.Name == podInfo.Name &&
		pod.Namespace == podInfo.Namespace &&
		pod.Status.PodIP == podInfo.Status.PodIP &&
		maps.Equal(pod.Annotations, podInfo.Annotations) &&
		maps.Equal(pod.Labels, podInfo.Labels) &&
		len(podInfo.OwnerReferences) == 1 &&
		reflect.DeepEqual(podInfo.OwnerReferences[0], expectedOwnerReference) &&
		reflect.DeepEqual(podInfo.WorkloadObject, workloadObject) &&
		reflect.DeepEqual(podInfo.WorkloadType, workloadType) &&
		pod.Spec.HostNetwork == podInfo.Spec.HostNetwork &&
		pod.Spec.NodeName == podInfo.Spec.NodeName
}

// hasAllRequiredFields checks if the necessary pod fields are available.
func hasAllRequiredFields(pod *corev1.Pod) bool {
	return pod.UID != "" &&
		pod.Name != "" &&
		pod.Namespace != "" &&
		pod.Status.PodIP != "" &&
		len(pod.Status.PodIPs) > 0 &&
		pod.Spec.NodeName != ""
}

// generatePodInfo creates a PodInfo from a Pod
func generatePodInfo(pod *corev1.Pod) *ciliumiov1alpha1.PodInfo {
	var podIPs []ciliumiov1alpha1.PodIP
	// Copy the Pod IPs into the PodInfo IPs.
	for _, podIP := range pod.Status.PodIPs {
		podIPs = append(podIPs, ciliumiov1alpha1.PodIP{IP: podIP.IP})
	}
	workloadObject, workloadType := podhelpers.GetWorkloadMetaFromPod(pod)
	controller := true
	blockOwnerDeletion := true
	return &ciliumiov1alpha1.PodInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name:        pod.Name,
			Namespace:   pod.Namespace,
			Labels:      pod.Labels,
			Annotations: pod.Annotations,
			// setting up owner reference to the pod will ensure that the PodInfo resource is deleted when the pod is deleted.
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         pod.APIVersion,
					Kind:               pod.Kind,
					Name:               pod.Name,
					UID:                pod.UID,
					Controller:         &controller,
					BlockOwnerDeletion: &blockOwnerDeletion,
				},
			},
		},
		Spec: ciliumiov1alpha1.PodInfoSpec{
			HostNetwork: pod.Spec.HostNetwork,
			NodeName:    pod.Spec.NodeName,
		},
		Status: ciliumiov1alpha1.PodInfoStatus{
			PodIP:  pod.Status.PodIP,
			PodIPs: podIPs,
		},
		WorkloadType:   workloadType,
		WorkloadObject: workloadObject,
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}).
		Owns(&ciliumiov1alpha1.PodInfo{}).
		Complete(r)
}
