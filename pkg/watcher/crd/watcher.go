// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package crd

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/tetragon/pkg/k8s/client/informers/externalversions"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/sensors"
	k8sconf "github.com/cilium/tetragon/pkg/watcher/conf"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
)

// Log "missing tracing policy" message once.
var logOnce sync.Once

func init() {
	runtime.ErrorHandlers = []func(error){k8sErrorHandler}
}

// k8sErrorHandler logs errors from k8s API to the tetragon logger for consistent log format.
func k8sErrorHandler(e error) {
	if e == nil {
		return
	}
	switch {
	case strings.Contains(e.Error(), "Failed to list *v1alpha1.TracingPolicy: the server could not find the requested resource (get tracingpolicies.cilium.io)"):
		// TODO: For now log an info message once if TracingPolicy is not defined.
		//       In the long term we should automate the CRD creation process.
		logOnce.Do(func() {
			logger.GetLogger().WithError(e).Infof("TracingPolicy CRD not defined")
		})
	default:
		logger.GetLogger().WithError(e).Errorf("Kubernetes API error")
	}
}

func addTracingPolicy(ctx context.Context, log logrus.FieldLogger, s *sensors.Manager,
	obj interface{},
) {
	var err error
	switch tp := obj.(type) {
	case *v1alpha1.TracingPolicy:
		log.WithField("policy", tp.TpInfo()).Info("adding tracing policy")
		err = s.AddTracingPolicy(ctx, tp)
	default:
		log.WithFields(logrus.Fields{
			"obj":      obj,
			"obj-type": fmt.Sprintf("%T", obj),
		}).Warn("addTracingPolicy: invalid type")
		return
	}

	if err != nil {
		log.WithError(err).Warn("adding tracing policy failed")
	}
}

func deleteTracingPolicy(ctx context.Context, log logrus.FieldLogger, s *sensors.Manager,
	obj interface{}) {

	if dfsu, ok := obj.(cache.DeletedFinalStateUnknown); ok {
		obj = dfsu.Obj
	}

	var err error
	switch tp := obj.(type) {
	case *v1alpha1.TracingPolicy:
		log.WithField("policy", tp.TpInfo()).Info("deleting tracing policy")
		err = s.DelTracingPolicy(ctx, tp.ObjectMeta.Name)
	}

	if err != nil {
		log.WithError(err).Warn("delete tracing policy failed")
	}
}

func updateTracingPolicy(ctx context.Context, log logrus.FieldLogger, s *sensors.Manager,
	oldObj interface{}, newObj interface{}) {
	var err error
	switch oldTp := oldObj.(type) {
	case *v1alpha1.TracingPolicy:
		newTp, ok := newObj.(*v1alpha1.TracingPolicy)
		if !ok {
			log.WithFields(logrus.Fields{
				"old-obj":      oldObj,
				"old-obj-type": fmt.Sprintf("%T", oldObj),
				"new-obj":      newObj,
				"new-obj-type": fmt.Sprintf("%T", newObj),
			}).Warn("updateTracingPolicy: invalid new type")
			return
		}

		// FIXME: add proper DeepEquals. The resource might have different
		//  resource versions but the fields that matter to us are still the
		//  same.
		if oldTp.ResourceVersion == newTp.ResourceVersion {
			return
		}

		log.WithFields(logrus.Fields{
			"old": oldTp.TpInfo(),
			"new": newTp.TpInfo(),
		}).Info("updating tracing policy")
		err = s.DelTracingPolicy(ctx, oldTp.ObjectMeta.Name)
		if err != nil {
			log.WithError(err).WithField(
				"old-policy", oldTp.TpInfo(),
			).Warnf("updateTracingPolicy: failed to remove old policy")
			return
		}

		err := s.AddTracingPolicy(ctx, newTp)
		if err != nil {
			log.WithError(err).WithField(
				"new-policy", newTp.TpInfo(),
			).Warnf("updateTracingPolicy: failed to add new policy")
			return
		}
	}
}

func WatchTracePolicy(ctx context.Context, s *sensors.Manager) {
	log := logger.GetLogger()
	conf, err := k8sconf.K8sConfig()
	if err != nil {
		log.WithError(err).Fatal("couldn't get cluster config")
	}
	client := versioned.NewForConfigOrDie(conf)
	factory := externalversions.NewSharedInformerFactory(client, 0)
	informer := factory.Cilium().V1alpha1().TracingPolicies()
	informer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			addTracingPolicy(ctx, log, s, obj)
		},
		DeleteFunc: func(obj interface{}) {
			deleteTracingPolicy(ctx, log, s, obj)
		},
		UpdateFunc: func(oldObj interface{}, newObj interface{}) {
			updateTracingPolicy(ctx, log, s, oldObj, newObj)
		}})

	go factory.Start(wait.NeverStop)
	factory.WaitForCacheSync(wait.NeverStop)
	log.Info("Started watching tracing policies")
}
