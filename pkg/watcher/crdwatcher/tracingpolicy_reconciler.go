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
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

// sensorManager is the subset of *sensors.Manager used by TracingPolicyReconciler.
// Defined where it is consumed so the Reconciler can be unit-tested with a fake.
type sensorManager interface {
	AddTracingPolicy(ctx context.Context, tp tracingpolicy.TracingPolicy) error
	DeleteTracingPolicy(ctx context.Context, name string, namespace string) error
}

// TracingPolicyReconciler reconciles cluster-scoped TracingPolicy resources.
//
// On a successful Get, it performs Delete+Add against sensors.Manager (the same
// semantics as the previous informer-based handler on Update). On NotFound, it
// performs Delete. Status-only updates are filtered out at the source via
// GenerationChangedPredicate, so they do not reach Reconcile.
type TracingPolicyReconciler struct {
	Client  client.Client
	Sensors sensorManager
}

// Reconcile drives Add/Delete on sensors.Manager from the live state of the
// TracingPolicy CR.
func (r *TracingPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logger.GetLogger().With("name", req.Name)

	tp := &v1alpha1.TracingPolicy{}
	err := r.Client.Get(ctx, req.NamespacedName, tp)
	if err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("deleting tracing policy")
			if delErr := r.Sensors.DeleteTracingPolicy(ctx, req.Name, ""); delErr != nil {
				log.Warn("delete tracing policy failed", logfields.Error, delErr)
			}
			return ctrl.Result{}, nil
		}
		log.Warn("failed to get tracing policy", logfields.Error, err)
		return ctrl.Result{}, err
	}

	// Spec changed (or new object): mirror the previous informer handler's
	// Delete+Add cycle. Delete is best-effort; Add is the real outcome.
	if delErr := r.Sensors.DeleteTracingPolicy(ctx, tp.TpName(), ""); delErr != nil {
		log.Debug("delete-before-add returned an error", logfields.Error, delErr)
	}
	log.Info("adding tracing policy", "info", tp.TpInfo())
	if addErr := r.Sensors.AddTracingPolicy(ctx, tp); addErr != nil {
		log.Warn("adding tracing policy failed", logfields.Error, addErr)
	}
	return ctrl.Result{}, nil
}

// SetupWithManager registers the Reconciler against the controller-runtime
// manager. GenerationChangedPredicate filters out status-only updates,
// finalizer changes, and annotation/label-only changes so they do not trigger
// BPF reloads.
func (r *TracingPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.TracingPolicy{},
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Complete(r)
}

// RegisterTracingPolicyReconciler installs the cluster-scoped TracingPolicy
// Reconciler against the controller-runtime manager. Registration is gated on
// the TracingPolicy CRD being present in the cluster — if it is not yet
// installed, the Reconciler will be registered as soon as it appears.
func RegisterTracingPolicyReconciler(cm controllerManager, s sensorManager) error {
	return cm.RegisterControllerWhenCRDReady(v1alpha1.TPName, func(mgr ctrl.Manager) error {
		r := &TracingPolicyReconciler{
			Client:  mgr.GetClient(),
			Sensors: s,
		}
		return r.SetupWithManager(mgr)
	})
}

// controllerManager is the subset of *manager.ControllerManager needed to
// install a CRD-gated Reconciler. Defined where it is consumed.
type controllerManager interface {
	RegisterControllerWhenCRDReady(crdName string, setup func(ctrl.Manager) error) error
}
