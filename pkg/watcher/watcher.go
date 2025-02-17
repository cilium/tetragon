// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package watcher

import (
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/tetragon/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/tetragon/pkg/k8s/client/informers/externalversions"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/reader/node"
)

type Watcher interface {
	AddInformer(name string, informer cache.SharedIndexInformer, indexers cache.Indexers) error
	GetInformer(name string) cache.SharedIndexInformer
	Start()
}

type K8sWatcher struct {
	K8sInformerFactory      informers.SharedInformerFactory        // for k8s built-in resources
	LocalK8sInformerFactory informers.SharedInformerFactory        // for k8s built-in resources local to the node
	CRDInformerFactory      externalversions.SharedInformerFactory // for Tetragon CRDs
	informers               map[string]cache.SharedIndexInformer
	deletedPodCache         *deletedPodCache
}

// NewK8sWatcher creates a new K8sWatcher with initialized informer factories.
func NewK8sWatcher(
	k8sClient kubernetes.Interface, crdClient versioned.Interface, stateSyncIntervalSec time.Duration,
) *K8sWatcher {
	var k8sInformerFactory, localK8sInformerFactory informers.SharedInformerFactory
	var crdInformerFactory externalversions.SharedInformerFactory

	if k8sClient != nil {
		k8sInformerFactory = informers.NewSharedInformerFactory(k8sClient, stateSyncIntervalSec)
		localK8sInformerFactory = informers.NewSharedInformerFactoryWithOptions(
			k8sClient, stateSyncIntervalSec, informers.WithTweakListOptions(
				func(options *metav1.ListOptions) {
					// watch local pods only
					options.FieldSelector = "spec.nodeName=" + node.GetNodeNameForExport()
				}))
	}
	if crdClient != nil {
		crdInformerFactory = externalversions.NewSharedInformerFactory(crdClient, stateSyncIntervalSec)
	}

	return &K8sWatcher{
		K8sInformerFactory:      k8sInformerFactory,
		LocalK8sInformerFactory: localK8sInformerFactory,
		CRDInformerFactory:      crdInformerFactory,
		informers:               make(map[string]cache.SharedIndexInformer),
	}
}

func (w *K8sWatcher) AddInformer(name string, informer cache.SharedIndexInformer, indexers cache.Indexers) error {
	w.informers[name] = informer

	err := informer.AddIndexers(indexers)
	if err != nil {
		return fmt.Errorf("failed to add indexers: %w", err)
	}

	return nil
}

func (w *K8sWatcher) GetInformer(name string) cache.SharedIndexInformer {
	return w.informers[name]
}

func (w *K8sWatcher) Start() {
	if w.K8sInformerFactory != nil {
		w.K8sInformerFactory.Start(wait.NeverStop)
		w.K8sInformerFactory.WaitForCacheSync(wait.NeverStop)
	}
	if w.LocalK8sInformerFactory != nil {
		w.LocalK8sInformerFactory.Start(wait.NeverStop)
		w.LocalK8sInformerFactory.WaitForCacheSync(wait.NeverStop)
	}
	if w.CRDInformerFactory != nil {
		w.CRDInformerFactory.Start(wait.NeverStop)
		w.CRDInformerFactory.WaitForCacheSync(wait.NeverStop)
	}
	for name, informer := range w.informers {
		logger.GetLogger().WithFields(logrus.Fields{
			"informer": name,
			"count":    len(informer.GetStore().ListKeys()),
		}).Info("Initialized informer cache")
	}
}
