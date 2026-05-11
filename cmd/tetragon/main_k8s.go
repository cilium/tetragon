// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !nok8s

package main

import (
	"context"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/manager"
	"github.com/cilium/tetragon/pkg/metrics"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/node"
	"github.com/cilium/tetragon/pkg/watcher"
	"github.com/cilium/tetragon/pkg/watcher/crdwatcher"
)

func initK8s(ctx context.Context) (watcher.PodAccessor, error) {
	var podAccessor watcher.PodAccessor
	var err error
	if option.K8SControlPlaneEnabled() {
		log.Info("Enabling Kubernetes API")
		// Start controller-runtime manager.
		controllerManager := manager.Get()
		controllerManager.Start(ctx)
		crds := make(map[string]struct{})
		// Both TracingPolicy CRDs are gated independently inside their
		// respective Reconciler-registration helpers, so neither appears
		// here. Only PodInfo still uses the upfront WaitCRDs gate.
		if option.Config.EnablePodInfo {
			crds[v1alpha1.PIName] = struct{}{}
		}
		if option.InClusterControlPlaneEnabled() {
			if len(crds) > 0 {
				err = controllerManager.WaitCRDs(ctx, crds)
				if err != nil {
					return nil, err
				}
			}
			podAccessor = controllerManager
			k8sNode, err := controllerManager.GetNode()
			if err != nil {
				log.Warn("Failed to get local Kubernetes node info. node_labels field will be empty", logfields.Error, err)
			} else {
				node.SetNodeLabels(k8sNode.Labels)
			}
		} else {
			podAccessor = watcher.NewFakeK8sWatcher(nil)
		}
	} else {
		log.Info("Disabling Kubernetes API")
		podAccessor = watcher.NewFakeK8sWatcher(nil)
	}

	return podAccessor, nil
}

func initK8sPolicyWatcher(_ context.Context) error {
	if option.K8SControlPlaneEnabled() && option.Config.EnableTracingPolicyCRD {
		log.Info("Enabling policy reconcilers")
		controllerManager := manager.Get()
		sensorManager := observer.GetSensorManager()
		// Cluster-scoped TracingPolicy: gated on its own CRD.
		if err := crdwatcher.RegisterTracingPolicyReconciler(controllerManager, sensorManager); err != nil {
			return err
		}
		// Namespaced TracingPolicy: gated independently on its own CRD, so
		// the cluster-scoped Reconciler still works if this CRD is absent.
		if err := crdwatcher.RegisterTracingPolicyNamespacedReconciler(controllerManager, sensorManager); err != nil {
			return err
		}
	}

	return nil
}

func initK8sMetrics() {
	go metrics.StartPodDeleteHandler()
	// Handler must be registered before the watcher is started
	metrics.RegisterPodDeleteHandler()
}
