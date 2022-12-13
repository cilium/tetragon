// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package crd

import (
	"context"
	"strings"
	"sync"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/tetragon/pkg/k8s/client/informers/externalversions"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"
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

func WatchTracePolicy(ctx context.Context, s *sensors.Manager) {
	log := logger.GetLogger()
	conf, err := rest.InClusterConfig()
	if err != nil {
		logger.GetLogger().WithError(err).Fatal("couldn't get cluster config")
	}
	client := versioned.NewForConfigOrDie(conf)
	factory := externalversions.NewSharedInformerFactory(client, 0)
	informer := factory.Cilium().V1alpha1().TracingPolicies()
	informer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			policy, ok := obj.(*v1alpha1.TracingPolicy)
			if !ok {
				log.WithField("obj", obj).Warn("invalid type in add func")
				return
			}
			log.WithField("policy", policy.Spec).Info("tracing policy added")
			err := s.AddTracingPolicy(ctx, policy.ObjectMeta.Name, policy)
			if err != nil {
				log.WithError(err).Warn("adding tracing policy failed")
			}
		},
		UpdateFunc: func(oldObj interface{}, newObj interface{}) {
			oldPolicy, ok := oldObj.(*v1alpha1.TracingPolicy)
			if !ok {
				logger.GetLogger().WithField("oldObj", oldObj).Warn("invalid oldObj type in update func")
				return
			}
			newPolicy, ok := newObj.(*v1alpha1.TracingPolicy)
			if !ok {
				logger.GetLogger().WithField("newObj", newObj).Warn("invalid newObj type in update func")
				return
			}
			/* Deep Equals */
			// FIXME: add proper DeepEquals. The resource might have different
			//  resource versions but the fields that matter to us are still the
			//  same.
			if oldPolicy.ResourceVersion == newPolicy.ResourceVersion {
				return
			}
			logger.GetLogger().WithFields(logrus.Fields{
				"oldPolicy": oldPolicy.Spec,
				"newPolicy": newPolicy.Spec,
			}).Info("tracing policy updated")
			err := s.DelTracingPolicy(ctx, oldPolicy.ObjectMeta.Name)
			if err != nil {
				log.WithError(err).Warnf("Failed to remove sensor %s to perform update", oldPolicy.ObjectMeta.Name)
				return
			}
			err = s.AddTracingPolicy(ctx, newPolicy.ObjectMeta.Name, newPolicy)
			if err != nil {
				log.WithError(err).Warn("adding new tracing policy failed")
			}

		},
		DeleteFunc: func(obj interface{}) {
			policy, ok := obj.(*v1alpha1.TracingPolicy)
			if !ok {
				dfsu, ok := obj.(cache.DeletedFinalStateUnknown)
				if ok {
					policy, ok = dfsu.Obj.(*v1alpha1.TracingPolicy)
				}
				if !ok {
					logger.GetLogger().WithField("obj", obj).Warn("invalid type in delete func")
					return
				}
			}
			logger.GetLogger().WithField("policy", policy.Spec).Info("tracing policy deleted")
			err := s.DelTracingPolicy(ctx, policy.ObjectMeta.Name)
			if err != nil {
				log.WithError(err).Warnf("Failed to remove sensor %s to perform update", policy.ObjectMeta.Name)
				return
			}

		},
	})
	go factory.Start(wait.NeverStop)
	factory.WaitForCacheSync(wait.NeverStop)
	logger.GetLogger().Info("Started watching tracing policies")
}
