// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !nok8s

package crdwatcher

import (
	"context"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
)

// TracingPolicyNamespacedReconciler reconciles namespaced TracingPolicy
// resources. Structurally identical to TracingPolicyReconciler, with the
// namespace propagated through Add/Delete calls into sensors.Manager.
type TracingPolicyNamespacedReconciler struct {
	Client  client.Client
	Sensors sensorManager
}

// Reconcile drives Add/Delete on sensors.Manager from the live state of the
// TracingPolicyNamespaced CR.
func (r *TracingPolicyNamespacedReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logger.GetLogger().With("name", req.Name, "namespace", req.Namespace)

	tp := &v1alpha1.TracingPolicyNamespaced{}
	err := r.Client.Get(ctx, req.NamespacedName, tp)
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("deleting namespaced tracing policy")
			if delErr := r.Sensors.DeleteTracingPolicy(ctx, req.Name, req.Namespace); delErr != nil {
				log.Warn("delete namespaced tracing policy failed", logfields.Error, delErr)
			}
			return ctrl.Result{}, nil
		}
		log.Warn("failed to get namespaced tracing policy", logfields.Error, err)
		return ctrl.Result{}, err
	}

	// Spec changed (or new object): mirror the cluster-scoped Reconciler's
	// Delete+Add cycle, namespace-aware.
	if delErr := r.Sensors.DeleteTracingPolicy(ctx, tp.TpName(), tp.TpNamespace()); delErr != nil {
		log.Debug("delete-before-add returned an error", logfields.Error, delErr)
	}
	log.Info("adding namespaced tracing policy", "info", tp.TpInfo())
	if addErr := r.Sensors.AddTracingPolicy(ctx, tp); addErr != nil {
		log.Warn("adding namespaced tracing policy failed", logfields.Error, addErr)
	}
	return ctrl.Result{}, nil
}

// SetupWithManager registers the Reconciler against the controller-runtime
// manager. GenerationChangedPredicate filters out status-only updates,
// finalizer changes, and annotation/label-only changes so they do not trigger
// BPF reloads.
func (r *TracingPolicyNamespacedReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.TracingPolicyNamespaced{},
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(r)
}

// RegisterTracingPolicyNamespacedReconciler installs the namespaced
// TracingPolicy Reconciler against the controller-runtime manager.
// Registration is gated on the TracingPolicyNamespaced CRD being present in
// the cluster — if it is not yet installed, the Reconciler will be registered
// as soon as it appears, independently of the cluster-scoped TracingPolicy
// CRD's availability.
func RegisterTracingPolicyNamespacedReconciler(cm controllerManager, s sensorManager) error {
	return cm.RegisterControllerWhenCRDReady(v1alpha1.TPNamespacedName, func(mgr ctrl.Manager) error {
		r := &TracingPolicyNamespacedReconciler{
			Client:  mgr.GetClient(),
			Sensors: s,
		}
		return r.SetupWithManager(mgr)
	})
}
