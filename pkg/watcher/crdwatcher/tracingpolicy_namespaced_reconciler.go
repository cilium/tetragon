// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !nok8s

package crdwatcher

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

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
			if delErr := r.Sensors.DeleteTracingPolicy(ctx, req.Name, req.Namespace, tp.TpDomain()); delErr != nil {
				log.Warn("delete namespaced tracing policy failed", logfields.Error, delErr)
			}
			return ctrl.Result{}, nil
		}
		log.Warn("failed to get namespaced tracing policy", logfields.Error, err)
		return ctrl.Result{}, err
	}

	// Spec changed (or new object): mirror the cluster-scoped Reconciler's
	// Delete+Add cycle, namespace-aware.
	if delErr := r.Sensors.DeleteTracingPolicy(ctx, tp.TpName(), tp.TpNamespace(), tp.TpDomain()); delErr != nil {
		log.Debug("delete-before-add returned an error", logfields.Error, delErr)
	}

	// spec.nodeSelector gates per-node loading. The Delete above already
	// unloaded any prior instance, so a policy whose nodeSelector stops matching
	// after an update is correctly left unloaded on this node.
	if skipForNode(ctx, r.Client, log, tp.Spec.NodeSelector) {
		log.Info("skipping namespaced tracing policy: node does not match spec.nodeSelector")
		return ctrl.Result{}, nil
	}

	log.Info("adding namespaced tracing policy", "info", tp.TpInfo())
	if addErr := r.Sensors.AddTracingPolicy(ctx, tp); addErr != nil {
		log.Error("adding namespaced tracing policy failed", logfields.Error, addErr)
		return ctrl.Result{}, reconcile.TerminalError(addErr)
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
		// Re-evaluate every policy's nodeSelector when the local node is
		// relabeled. Filter to the local node, and to label changes only so
		// frequent status/heartbeat updates do not trigger reloads.
		Watches(&corev1.Node{},
			handler.EnqueueRequestsFromMapFunc(r.mapNodeToPolicies),
			builder.WithPredicates(
				predicate.LabelChangedPredicate{},
				predicate.NewPredicateFuncs(isLocalNode),
			)).
		Complete(r)
}

// mapNodeToPolicies enqueues every TracingPolicyNamespaced that uses a
// nodeSelector. It is wired to the local Node (filtered to label changes) so a
// relabel re-evaluates each such policy. Policies without a nodeSelector always
// match, so they are skipped to avoid needlessly reloading them on every
// relabel.
func (r *TracingPolicyNamespacedReconciler) mapNodeToPolicies(ctx context.Context, _ client.Object) []reconcile.Request {
	var list v1alpha1.TracingPolicyNamespacedList
	if err := r.Client.List(ctx, &list); err != nil {
		logger.GetLogger().Warn("nodeSelector: listing namespaced tracing policies after node change failed", logfields.Error, err)
		return nil
	}
	reqs := make([]reconcile.Request, 0, len(list.Items))
	for i := range list.Items {
		if list.Items[i].Spec.NodeSelector == nil {
			continue
		}
		reqs = append(reqs, reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name:      list.Items[i].Name,
				Namespace: list.Items[i].Namespace,
			},
		})
	}
	return reqs
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
