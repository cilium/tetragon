// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package crdwatcher

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/tetragon/pkg/logger/logfields"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"

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
func k8sErrorHandler(_ context.Context, e error, _ string, _ ...interface{}) {
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

func addTracingPolicy(ctx context.Context, log logger.FieldLogger, s *sensors.Manager,
	obj interface{},
) {
	var err error
	switch tp := obj.(type) {
	case *v1alpha1.TracingPolicy:
		log.Info("adding tracing policy", "name", tp.TpName(), "info", tp.TpInfo())
		err = s.AddTracingPolicy(ctx, tp)
	case *v1alpha1.TracingPolicyNamespaced:
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

func deleteTracingPolicy(ctx context.Context, log logger.FieldLogger, s *sensors.Manager,
	obj interface{}) {

	if dfsu, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		obj = dfsu.Obj
	}

	var err error
	switch tp := obj.(type) {
	case *v1alpha1.TracingPolicy:
		log.Info("deleting tracing policy", "name", tp.TpName(), "info", tp.TpInfo())
		err = s.DeleteTracingPolicy(ctx, tp.TpName(), "")

	case *v1alpha1.TracingPolicyNamespaced:
		log.Info("deleting namespaced tracing policy", "name", tp.TpName(), "info", tp.TpInfo(), "namespace", tp.TpNamespace())
		err = s.DeleteTracingPolicy(ctx, tp.TpName(), tp.TpNamespace())
	}

	if err != nil {
		log.Warn("delete tracing policy failed", logfields.Error, err)
	}
}

func updateTracingPolicy(ctx context.Context, log logger.FieldLogger, s *sensors.Manager,
	oldObj interface{}, newObj interface{}) {

	update := func(oldTp, newTp tracingpolicy.TracingPolicy) {
		var namespace string
		if oldTpNs, ok := oldTp.(tracingpolicy.TracingPolicyNamespaced); ok {
			namespace = oldTpNs.TpNamespace()
		}

		if err := s.DeleteTracingPolicy(ctx, oldTp.TpName(), namespace); err != nil {
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
			AddFunc: func(obj interface{}) {
				addTracingPolicy(ctx, log, s, obj)
			},
			DeleteFunc: func(obj interface{}) {
				deleteTracingPolicy(ctx, log, s, obj)
			},
			UpdateFunc: func(oldObj interface{}, newObj interface{}) {
				updateTracingPolicy(ctx, log, s, oldObj, newObj)
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
			AddFunc: func(obj interface{}) {
				addTracingPolicy(ctx, log, s, obj)
			},
			DeleteFunc: func(obj interface{}) {
				deleteTracingPolicy(ctx, log, s, obj)
			},
			UpdateFunc: func(oldObj interface{}, newObj interface{}) {
				updateTracingPolicy(ctx, log, s, oldObj, newObj)
			}})
	if err != nil {
		return err
	}

	return nil
}
