// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package crd

import (
	"context"
	"fmt"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/tetragon/pkg/k8s/client/informers/externalversions"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/runtimesecuritypolicy"
	"github.com/cilium/tetragon/pkg/sensors"
	k8sconf "github.com/cilium/tetragon/pkg/watcher/conf"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
)

func addRuntimeSecurityPolicy(ctx context.Context, log logrus.FieldLogger, s *sensors.Manager,
	obj interface{},
) {
	switch rsp := obj.(type) {
	case *v1alpha1.RuntimeSecurityPolicy:
		if rsp != nil {
			log.WithField("name", rsp.Name).Info("converting RuntimeSecurityPolicy and adding TracingPolicy")
			tp, err := runtimesecuritypolicy.ToTracingPolicy(*rsp)
			if err != nil {
				log.WithError(err).WithField("name", rsp.Name).Warn("converting RuntimeSecurityPolicy failed")
				return
			}
			err = s.AddTracingPolicy(ctx, tp)
			if err != nil {
				log.WithError(err).WithField("name", rsp.Name).Warn("adding RuntimeSecurityPolicy failed")
				return
			}
		}
	default:
		log.WithFields(logrus.Fields{
			"obj":      obj,
			"obj-type": fmt.Sprintf("%T", obj),
		}).Warn("addRuntimeSecurityPolicy: invalid type")
		return
	}
}

func deleteRuntimeSecurityPolicy(ctx context.Context, log logrus.FieldLogger, s *sensors.Manager,
	obj interface{},
) {
	switch rsp := obj.(type) {
	case *v1alpha1.RuntimeSecurityPolicy:
		if rsp != nil {
			log.WithField("name", rsp.Name).Info("deleting TracingPolicy associated with RuntimeSecurityPolicy")
			err := s.DeleteTracingPolicy(ctx, rsp.Name, rsp.Namespace)
			if err != nil {
				log.WithError(err).WithField("name", rsp.Name).Warn("deleting RuntimeSecurityPolicy failed")
				return
			}
		}
	default:
		log.WithFields(logrus.Fields{
			"obj":      obj,
			"obj-type": fmt.Sprintf("%T", obj),
		}).Warn("deleteRuntimeSecurityPolicy: invalid type")
		return
	}
}

// func updateTracingPolicy(ctx context.Context, log logrus.FieldLogger, s *sensors.Manager,
// 	oldObj interface{}, newObj interface{}) {

// 	update := func(oldTp, newTp tracingpolicy.TracingPolicy) {
// 		if err := s.DeleteTracingPolicy(ctx, oldTp.TpName()); err != nil {
// 			log.WithError(err).WithField(
// 				"old-name", oldTp.TpName(),
// 			).Warnf("updateTracingPolicy: failed to remove old policy")
// 			return
// 		}
// 		if err := s.AddTracingPolicy(ctx, newTp); err != nil {
// 			log.WithError(err).WithField(
// 				"new-name", newTp.TpName(),
// 			).Warnf("updateTracingPolicy: failed to add new policy")
// 			return
// 		}
// 	}

// 	var err error
// 	switch oldTp := oldObj.(type) {
// 	case *v1alpha1.TracingPolicy:
// 		newTp, ok := newObj.(*v1alpha1.TracingPolicy)
// 		if !ok {
// 			err = fmt.Errorf("type mismatch")
// 			break
// 		}
// 		// FIXME: add proper DeepEquals. The resource might have different
// 		//  resource versions but the fields that matter to us are still the
// 		//  same.
// 		if oldTp.ResourceVersion == newTp.ResourceVersion {
// 			return
// 		}

// 		log.WithFields(logrus.Fields{
// 			"old": oldTp.TpName(),
// 			"new": newTp.TpName(),
// 		}).Info("updating tracing policy")
// 		update(oldTp, newTp)

// 	case *v1alpha1.TracingPolicyNamespaced:
// 		newTp, ok := newObj.(*v1alpha1.TracingPolicyNamespaced)
// 		if !ok {
// 			err = fmt.Errorf("type mismatch")
// 			break
// 		}
// 		// FIXME: add proper DeepEquals. The resource might have different
// 		//  resource versions but the fields that matter to us are still the
// 		//  same.
// 		if oldTp.ResourceVersion == newTp.ResourceVersion {
// 			return
// 		}

// 		log.WithFields(logrus.Fields{
// 			"old": oldTp.TpName(),
// 			"new": newTp.TpName(),
// 		}).Info("updating namespaced tracing policy")
// 		update(oldTp, newTp)
// 	}

// 	if err != nil {
// 		log.WithFields(logrus.Fields{
// 			"old-obj":      oldObj,
// 			"old-obj-type": fmt.Sprintf("%T", oldObj),
// 			"new-obj":      newObj,
// 			"new-obj-type": fmt.Sprintf("%T", newObj),
// 		}).Warnf("updateTracingPolicy: %s", err.Error())
// 	}
// }

func WatchRuntimeSecurityPolicy(ctx context.Context, s *sensors.Manager) {
	log := logger.GetLogger()
	conf, err := k8sconf.K8sConfig()
	if err != nil {
		log.WithError(err).Fatal("couldn't get cluster config")
	}
	client := versioned.NewForConfigOrDie(conf)
	factory := externalversions.NewSharedInformerFactory(client, 0)

	factory.Cilium().V1alpha1().TracingPolicies().Informer().AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				addRuntimeSecurityPolicy(ctx, log, s, obj)
			},
			DeleteFunc: func(obj interface{}) {
				deleteRuntimeSecurityPolicy(ctx, log, s, obj)
			},
			UpdateFunc: func(oldObj interface{}, newObj interface{}) {
				// updateTracingPolicy(ctx, log, s, oldObj, newObj)
			}})

	go factory.Start(wait.NeverStop)
	factory.WaitForCacheSync(wait.NeverStop)
	log.Info("Started watching runtime security policies")
}
