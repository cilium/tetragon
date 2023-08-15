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

package controller

import (
	"context"

	ciliumiov1alpha1 "github.com/cilium/tetragon/tetragonpod/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// TetragonPodReconciler reconciles a TetragonPod object
type TetragonPodReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=cilium.io,resources=TetragonPods,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=cilium.io,resources=TetragonPods/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=cilium.io,resources=TetragonPods/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.

// Reconcile is the main loop of the controller that something changes with the pod resources in the cluster.
func (r *TetragonPodReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	l := log.FromContext(ctx)

	// Get the Pod.
	pod := &corev1.Pod{}
	if err := r.Get(ctx, req.NamespacedName, pod); err != nil {

		// CASE 1: Pod is deleted, therefore delete the corresponding tetragonPod resource.
		if client.IgnoreNotFound(err) == nil {
			l.Info("Pod Deleted: ", "Name", req.Name, " Namespace", req.Namespace)
			r.deleteTetragonPod(ctx, req)
			return ctrl.Result{}, nil
		}
		// Error fetching the pod.
		l.Error(err, "unable to fetch Pod")
		return ctrl.Result{}, err
	}

	// CASE 2: Pod is created or updated.
	// wait until the necessary pod fields are available.
	if checkIfReady(pod) == false {
		return ctrl.Result{}, nil
	}

	// The needed fields are ready, therefore create or update the corresponding tetragonPod resource.
	// Check if corresponding tetragonPod already exists and has changed.
	tetragonPod, existsAndChanged := r.checkExistsAndChanged(ctx, req, pod)
	if existsAndChanged && tetragonPod != nil {
		// CASE 2.1: TetragonPod already exists, and the pod hsa changed, update it.
		l.Info("Pod Updated: ", "Name", req.Name, "Namespace", req.Namespace)
		r.updateTetragonPod(ctx, pod, tetragonPod)
		return ctrl.Result{}, nil
	} else if tetragonPod == nil {
		// pod not found
		return ctrl.Result{}, nil
	}

	// CASE 3: TetragonPod does not exist, create new.
	l.Info("Pod Created: ", "Name", req.Name, "Namespace", req.Namespace)
	r.createTetragonPod(ctx, pod)
	return ctrl.Result{}, nil
}

// checkExistsAndChanged checks if the corresponding tetragonPod resource already exists.
func (r *TetragonPodReconciler) checkExistsAndChanged(ctx context.Context, req ctrl.Request, pod *corev1.Pod) (*ciliumiov1alpha1.TetragonPod, bool) {

	// check if the tetragonPod already exists for that pod.
	tetragonPod, err := r.getTetragonPod(ctx, req)
	if err != nil {
		return nil, false
	}
	// checkIfChanged returns true if the pod and tetragonPod do not match.
	if checkIfChanged(pod, tetragonPod) {
		return tetragonPod, true
	}
	return tetragonPod, false

}

// checkIfChanged returns true if the pod has changed.
func checkIfChanged(pod *corev1.Pod, tetragonPod *ciliumiov1alpha1.TetragonPod) bool {
	podStringFields := []string{
		pod.Name,
		pod.Namespace,
		pod.Status.PodIP,
	}

	podNumFields := []int{
		len(pod.Status.PodIPs),
		len(pod.Labels),
		len(pod.Annotations),
	}

	tetragonPodStringFields := []string{
		tetragonPod.Name,
		tetragonPod.Namespace,
		tetragonPod.Status.PodIP,
	}

	tetragonPodNumFields := []int{
		len(tetragonPod.Status.PodIPs),
		len(tetragonPod.Labels),
		len(tetragonPod.Annotations),
	}

	// check string fields
	for index := range podStringFields {
		if podStringFields[index] != tetragonPodStringFields[index] {
			return true
		}
	}

	// check num fields
	for index := range podNumFields {
		if podNumFields[index] != tetragonPodNumFields[index] {
			return true
		}
	}

	// check UID field
	if pod.UID == types.UID("") {
		return true
	}

	// check owner reference
	if ownerReferenceChanged(pod, tetragonPod) {
		return true
	}

	return false
}

// ownerReferenceChanged returns true if the owner of the tetragonPod has changed.
func ownerReferenceChanged(pod *corev1.Pod, tetragonPod *ciliumiov1alpha1.TetragonPod) bool {
	ownerReference := tetragonPod.OwnerReferences[0]
	if ownerReference.Name != pod.Name || ownerReference.UID != pod.UID || ownerReference.Kind != pod.Kind || ownerReference.APIVersion != pod.APIVersion {
		return true
	}
	return false
}

// checkIfReady checks if the necessary pod fields are available.
func checkIfReady(pod *corev1.Pod) bool {
	requiredStringFields := []string{
		pod.Name,
		pod.Namespace,
		pod.Status.PodIP,
		pod.APIVersion,
		pod.Kind,
	}

	requiredNumFields := []int{
		len(pod.Status.PodIPs),
		len(pod.Labels),
		len(pod.Annotations),
	}

	// check string fields
	for _, field := range requiredStringFields {
		if field == "" {
			return false
		}
	}

	// check num fields
	for _, field := range requiredNumFields {
		if field == 0 {
			return false
		}
	}

	// check UID field
	if pod.UID == types.UID("") {
		return false
	}

	return true
}

// deleteTetragonPod deletes the corresponding tetragonPod resource.
func (r *TetragonPodReconciler) deleteTetragonPod(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// get the logger from pre-defined context
	l := log.FromContext(ctx)

	// create the pod to be deleted
	tetragonPodToDelete := &ciliumiov1alpha1.TetragonPod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      req.Name,
			Namespace: req.Namespace,
		},
	}

	// Check if corresponding tetragonPod resource exists
	if err := r.Get(ctx, req.NamespacedName, tetragonPodToDelete); err != nil {
		l.Error(err, "Corresponding tetragonPod Resource does not exist")
		return ctrl.Result{}, err
	}

	// Delete the Pod
	if err := r.Delete(ctx, tetragonPodToDelete); err != nil {
		l.Error(err, "Failed to delete the tetragonPod resource")
		return ctrl.Result{}, err
	}

	// Pod deleted successfully.
	l.Info("TetragonPod deleted successfully")
	return ctrl.Result{}, nil
}

// updateTetragonPod updates the corresponding tetragonPod resource.
func (r *TetragonPodReconciler) updateTetragonPod(ctx context.Context, pod *corev1.Pod, tetragonPod *ciliumiov1alpha1.TetragonPod) (ctrl.Result, error) {
	l := log.FromContext(ctx)
	l.Info("Updating the corresponding tetragonPod resource")

	// get the updated fields to be mapped to the tetragonPod resource.
	updatedIP := ciliumiov1alpha1.PodIP{IP: pod.Status.PodIP}
	updatedPodIPs := append([]ciliumiov1alpha1.PodIP{updatedIP}, tetragonPod.Status.PodIPs...)
	updatedOwnerReference := metav1.OwnerReference{
		Name:       pod.Name,
		UID:        pod.UID,
		Kind:       pod.Kind,
		APIVersion: pod.APIVersion,
	}

	// update the fields of the tetragonPod resource.
	tetragonPod.Name = pod.Name
	tetragonPod.Labels = pod.Labels
	tetragonPod.Annotations = pod.Annotations
	tetragonPod.Status.PodIP = updatedIP.IP
	tetragonPod.Status.PodIPs = updatedPodIPs
	tetragonPod.OwnerReferences = []metav1.OwnerReference{updatedOwnerReference}

	// Update the tetragonPod resource.
	if err := r.Update(ctx, tetragonPod); err != nil {
		l.Error(err, "Failed to update the tetragonPod resource")
		return ctrl.Result{}, err
	}
	l.Info("TetragonPod updated successfully")
	return ctrl.Result{}, nil
}

// createTetragonPod creates a tetragonPod resource.
func (r *TetragonPodReconciler) createTetragonPod(ctx context.Context, pod *corev1.Pod) (ctrl.Result, error) {
	l := log.FromContext(ctx)
	// create the tetragon pod since the pod exists
	if pod.Status.Phase == corev1.PodRunning {
		l.Info("Creating the corresponding tetragonPod resource")
		tetragonPod := generatePod(pod)

		if err := r.Create(ctx, tetragonPod); err != nil {
			l.Error(err, "Failed to create TetragonPod")
			return ctrl.Result{}, err
		}
		l.Info("New TetragonPod creation Successful")
		return ctrl.Result{}, nil
	}
	return ctrl.Result{}, nil
}

// generatePod takes a pod as an input and generates a tetragonPod resource, using the following fields:
// - Name
// - Namespace
// - Labels
// - Annotations
// - OwnerReferences
// - PodIPs
func generatePod(pod *corev1.Pod) *ciliumiov1alpha1.TetragonPod {
	podIPs := []ciliumiov1alpha1.PodIP{}
	// Copy the Pod IPs into the TetragonPod IPs.
	for _, podIP := range pod.Status.PodIPs {
		podIPs = append(podIPs, ciliumiov1alpha1.PodIP{IP: podIP.IP})
	}
	return &ciliumiov1alpha1.TetragonPod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        pod.Name,
			Namespace:   pod.Namespace,
			Labels:      pod.Labels,
			Annotations: pod.Annotations,
			// setting up ownder reference to the pod will ensure that the tetragonPod resource is deleted when the pod is deleted.
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: pod.APIVersion,
					Kind:       pod.Kind,
					Name:       pod.Name,
					UID:        pod.UID,
				},
			},
		},
		Status: ciliumiov1alpha1.TetragonPodStatus{
			PodIP:  pod.Status.PodIP,
			PodIPs: podIPs,
		},
	}
}

// getTetragonPod gets the tetragonPod resource
func (r *TetragonPodReconciler) getTetragonPod(ctx context.Context, req ctrl.Request) (*ciliumiov1alpha1.TetragonPod, error) {
	l := log.FromContext(ctx)
	tetragonPod := &ciliumiov1alpha1.TetragonPod{}
	if err := r.Get(ctx, req.NamespacedName, tetragonPod); err != nil {
		if client.IgnoreNotFound(err) == nil {
			l.Info("TetragonPod does not exist: Name=", req.Name, " Namespace=", req.Namespace)
			return nil, err
		}

		l.Error(err, "error getting TetragonPod")
		return nil, err
	}
	return tetragonPod, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *TetragonPodReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Pod{}).
		Owns(&ciliumiov1alpha1.TetragonPod{}).
		Complete(r)
}
