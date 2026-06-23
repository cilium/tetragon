// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !nok8s

package crdwatcher

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/tetragon/pkg/logger/logfields"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	slimlabels "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/labels"
	slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/manager"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

// Log "missing tracing policy" message once.
var logOnce sync.Once

func init() {
	runtime.ErrorHandlers = []runtime.ErrorHandler{k8sErrorHandler}
}

// k8sErrorHandler logs errors from k8s API to the tetragon logger for consistent log format.
func k8sErrorHandler(_ context.Context, e error, _ string, _ ...any) {
	if e == nil {
		return
	}
	switch {
	case strings.Contains(e.Error(), "Failed to list *v1alpha1.TracingPolicy: the server could not find the requested resource (get tracingpolicies.cilium.io)"):
		// TODO: For now log an info message once if TracingPolicy is not defined.
		//       In the long term we should automate the CRD creation process.
		logOnce.Do(func() {
			logger.GetLogger().Info("TracingPolicy CRD not defined", logfields.Error, e)
		})
	default:
		logger.GetLogger().Error("Kubernetes API error", logfields.Error, e)
	}
}

func addTracingPolicy(ctx context.Context, log logger.FieldLogger, m *manager.ControllerManager, s *sensors.Manager,
	obj any,
) {
	var err error
	switch tp := obj.(type) {
	case *v1alpha1.TracingPolicy:
		applies, applyErr := tracingPolicyAppliesToLocalNode(m, tp)
		if applyErr != nil {
			log.Warn("failed to evaluate tracing policy nodeSelector", "name", tp.TpName(), "namespace", tp.TpNamespace(), logfields.Error, applyErr)
			return
		}
		if !applies {
			log.Info("skipping tracing policy due to nodeSelector", "name", tp.TpName(), "info", tp.TpInfo())
			return
		}
		log.Info("adding tracing policy", "name", tp.TpName(), "info", tp.TpInfo())
		err = s.AddTracingPolicy(ctx, tp)
	case *v1alpha1.TracingPolicyNamespaced:
		applies, applyErr := tracingPolicyAppliesToLocalNode(m, tp)
		if applyErr != nil {
			log.Warn("failed to evaluate namespaced tracing policy nodeSelector", "name", tp.TpName(), "namespace", tp.TpNamespace(), logfields.Error, applyErr)
			return
		}
		if !applies {
			log.Info("skipping namespaced tracing policy due to nodeSelector", "name", tp.TpName(), "info", tp.TpInfo(), "namespace", tp.TpNamespace())
			return
		}
		log.Info("adding namespaced tracing policy", "name", tp.TpName(), "info", tp.TpInfo(), "namespace", tp.TpNamespace())
		err = s.AddTracingPolicy(ctx, tp)
	default:
		log.Warn("addTracingPolicy: invalid type", "obj", obj, "obj-type", fmt.Sprintf("%T", obj))
		return
	}

	if err != nil {
		log.Warn("adding tracing policy failed", logfields.Error, err)
	}
}

func nodeSelectorMatches(nodeSelector *slimv1.LabelSelector, nodeLabels map[string]string) (bool, error) {
	if nodeSelector == nil {
		return true, nil
	}
	selector, err := slimv1.LabelSelectorAsSelector(nodeSelector)
	if err != nil {
		return false, err
	}
	return selector.Matches(slimlabels.Set(nodeLabels)), nil
}

func tracingPolicyNodeSelector(tp tracingpolicy.TracingPolicy) *slimv1.LabelSelector {
	if tp == nil || tp.TpSpec() == nil {
		return nil
	}
	return tp.TpSpec().NodeSelector
}

func tracingPolicyAppliesToNode(tp tracingpolicy.TracingPolicy, node *corev1.Node) (bool, error) {
	if node == nil {
		return false, nil
	}
	return nodeSelectorMatches(tracingPolicyNodeSelector(tp), node.Labels)
}

func tracingPolicyAppliesToLocalNode(m *manager.ControllerManager, tp tracingpolicy.TracingPolicy) (bool, error) {
	if tracingPolicyNodeSelector(tp) == nil {
		return true, nil
	}
	node, err := m.GetNode()
	if err != nil {
		return false, err
	}
	return tracingPolicyAppliesToNode(tp, node)
}

func reconcileTracingPolicyNodeSelector(ctx context.Context, log logger.FieldLogger, s *sensors.Manager,
	oldNode *corev1.Node, newNode *corev1.Node, obj any,
) {
	var tp tracingpolicy.TracingPolicy
	switch policy := obj.(type) {
	case *v1alpha1.TracingPolicy:
		tp = policy
	case *v1alpha1.TracingPolicyNamespaced:
		tp = policy
	default:
		log.Warn("reconcileTracingPolicyNodeSelector: invalid type", "obj", obj, "obj-type", fmt.Sprintf("%T", obj))
		return
	}

	oldApplies, err := tracingPolicyAppliesToNode(tp, oldNode)
	if err != nil {
		log.Warn("failed to evaluate old local node labels for tracing policy nodeSelector", "name", tp.TpName(), "namespace", tp.TpNamespace(), logfields.Error, err)
		return
	}
	newApplies, err := tracingPolicyAppliesToNode(tp, newNode)
	if err != nil {
		log.Warn("failed to evaluate new local node labels for tracing policy nodeSelector", "name", tp.TpName(), "namespace", tp.TpNamespace(), logfields.Error, err)
		return
	}

	switch {
	case oldApplies == newApplies:
		return
	case newApplies:
		log.Info("adding tracing policy due to nodeSelector match", "name", tp.TpName(), "namespace", tp.TpNamespace(), "info", tp.TpInfo())
		if err := s.AddTracingPolicy(ctx, tp); err != nil {
			log.Warn("failed to add tracing policy after nodeSelector match", "name", tp.TpName(), "namespace", tp.TpNamespace(), logfields.Error, err)
		}
	default:
		log.Info("deleting tracing policy due to nodeSelector mismatch", "name", tp.TpName(), "namespace", tp.TpNamespace(), "info", tp.TpInfo())
		if err := s.DeleteTracingPolicy(ctx, tp.TpName(), tp.TpNamespace(), tp.TpDomain()); err != nil {
			log.Warn("failed to delete tracing policy after nodeSelector mismatch", "name", tp.TpName(), "namespace", tp.TpNamespace(), logfields.Error, err)
		}
	}
}

func deleteTracingPolicy(ctx context.Context, log logger.FieldLogger, s *sensors.Manager,
	obj any) {

	if dfsu, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		obj = dfsu.Obj
	}

	var err error
	switch tp := obj.(type) {
	case *v1alpha1.TracingPolicy:
		log.Info("deleting tracing policy", "name", tp.TpName(), "info", tp.TpInfo())
		err = s.DeleteTracingPolicy(ctx, tp.TpName(), "", tp.TpDomain())

	case *v1alpha1.TracingPolicyNamespaced:
		log.Info("deleting namespaced tracing policy", "name", tp.TpName(), "info", tp.TpInfo(), "namespace", tp.TpNamespace())
		err = s.DeleteTracingPolicy(ctx, tp.TpName(), tp.TpNamespace(), tp.TpDomain())
	}

	if err != nil {
		log.Warn("delete tracing policy failed", logfields.Error, err)
	}
}

func updateTracingPolicy(ctx context.Context, log logger.FieldLogger, m *manager.ControllerManager, s *sensors.Manager,
	oldObj any, newObj any) {

	update := func(oldTp, newTp tracingpolicy.TracingPolicy) {
		namespace := oldTp.TpNamespace()
		oldApplies, err := tracingPolicyAppliesToLocalNode(m, oldTp)
		if err != nil {
			log.Warn("updateTracingPolicy: failed to evaluate old policy nodeSelector", "old-name", oldTp.TpName(), logfields.Error, err)
			return
		}
		newApplies, err := tracingPolicyAppliesToLocalNode(m, newTp)
		if err != nil {
			log.Warn("updateTracingPolicy: failed to evaluate new policy nodeSelector", "new-name", newTp.TpName(), logfields.Error, err)
			return
		}

		switch {
		case !oldApplies && !newApplies:
			return
		case !oldApplies && newApplies:
			if err := s.AddTracingPolicy(ctx, newTp); err != nil {
				log.Warn("updateTracingPolicy: failed to add new policy", "new-name", newTp.TpName(), logfields.Error, err)
			}
			return
		case oldApplies && !newApplies:
			if err := s.DeleteTracingPolicy(ctx, oldTp.TpName(), namespace, oldTp.TpDomain()); err != nil {
				log.Warn("updateTracingPolicy: failed to remove old policy", "old-name", oldTp.TpName(), logfields.Error, err)
			}
			return
		}

		if err := s.DeleteTracingPolicy(ctx, oldTp.TpName(), namespace, oldTp.TpDomain()); err != nil {
			log.Warn("updateTracingPolicy: failed to remove old policy", "old-name", oldTp.TpName(), logfields.Error, err)
			return
		}
		if err := s.AddTracingPolicy(ctx, newTp); err != nil {
			log.Warn("updateTracingPolicy: failed to add new policy", "new-name", newTp.TpName(), logfields.Error, err)
			return
		}
	}

	var err error
	switch oldTp := oldObj.(type) {
	case *v1alpha1.TracingPolicy:
		newTp, ok := newObj.(*v1alpha1.TracingPolicy)
		if !ok {
			err = errors.New("type mismatch")
			break
		}
		// FIXME: add proper DeepEquals. The resource might have different
		//  resource versions but the fields that matter to us are still the
		//  same.
		if oldTp.ResourceVersion == newTp.ResourceVersion {
			return
		}

		log.Info("updating tracing policy", "old", oldTp.TpName(), "new", newTp.TpName())
		update(oldTp, newTp)

	case *v1alpha1.TracingPolicyNamespaced:
		newTp, ok := newObj.(*v1alpha1.TracingPolicyNamespaced)
		if !ok {
			err = errors.New("type mismatch")
			break
		}
		// FIXME: add proper DeepEquals. The resource might have different
		//  resource versions but the fields that matter to us are still the
		//  same.
		if oldTp.ResourceVersion == newTp.ResourceVersion {
			return
		}

		log.Info("updating namespaced tracing policy", "old", oldTp.TpName(), "new", newTp.TpName())
		update(oldTp, newTp)
	}

	if err != nil {
		log.Warn("updateTracingPolicy error",
			logfields.Error, err,
			"old-obj", oldObj,
			"old-obj-type", fmt.Sprintf("%T", oldObj),
			"new-obj", newObj,
			"new-obj-type", fmt.Sprintf("%T", newObj))
	}
}

func AddTracingPolicyInformer(ctx context.Context, m *manager.ControllerManager, s *sensors.Manager) error {
	log := logger.GetLogger()
	tpInformer, err := m.Manager.GetCache().GetInformer(ctx, &v1alpha1.TracingPolicy{})
	if err != nil {
		return err
	}
	_, err = tpInformer.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj any) {
				addTracingPolicy(ctx, log, m, s, obj)
			},
			DeleteFunc: func(obj any) {
				deleteTracingPolicy(ctx, log, s, obj)
			},
			UpdateFunc: func(oldObj any, newObj any) {
				updateTracingPolicy(ctx, log, m, s, oldObj, newObj)
			}})
	if err != nil {
		return err
	}

	tpnInformer, err := m.Manager.GetCache().GetInformer(ctx, &v1alpha1.TracingPolicyNamespaced{})
	if err != nil {
		return err
	}
	_, err = tpnInformer.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj any) {
				addTracingPolicy(ctx, log, m, s, obj)
			},
			DeleteFunc: func(obj any) {
				deleteTracingPolicy(ctx, log, s, obj)
			},
			UpdateFunc: func(oldObj any, newObj any) {
				updateTracingPolicy(ctx, log, m, s, oldObj, newObj)
			}})
	if err != nil {
		return err
	}

	nodeInformer, err := m.Manager.GetCache().GetInformer(ctx, &corev1.Node{})
	if err != nil {
		return err
	}
	_, err = nodeInformer.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			UpdateFunc: func(oldObj any, newObj any) {
				oldNode, oldOK := oldObj.(*corev1.Node)
				newNode, newOK := newObj.(*corev1.Node)
				if !oldOK || !newOK {
					log.Warn("node update: invalid type", "old-obj-type", fmt.Sprintf("%T", oldObj), "new-obj-type", fmt.Sprintf("%T", newObj))
					return
				}

				var tpList v1alpha1.TracingPolicyList
				if err := m.Manager.GetCache().List(ctx, &tpList); err != nil {
					log.Warn("failed to list tracing policies for nodeSelector reconciliation", logfields.Error, err)
					return
				}
				for i := range tpList.Items {
					reconcileTracingPolicyNodeSelector(ctx, log, s, oldNode, newNode, &tpList.Items[i])
				}

				var tpnList v1alpha1.TracingPolicyNamespacedList
				if err := m.Manager.GetCache().List(ctx, &tpnList); err != nil {
					log.Warn("failed to list namespaced tracing policies for nodeSelector reconciliation", logfields.Error, err)
					return
				}
				for i := range tpnList.Items {
					reconcileTracingPolicyNodeSelector(ctx, log, s, oldNode, newNode, &tpnList.Items[i])
				}
			},
		})
	if err != nil {
		return err
	}

	return nil
}
