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
	GetK8sInformerFactory() informers.SharedInformerFactory
	GetLocalK8sInformerFactory() informers.SharedInformerFactory
	GetCRDInformerFactory() externalversions.SharedInformerFactory
}

type K8sWatcher struct {
	k8sInformerFactory      informers.SharedInformerFactory        // for k8s built-in resources
	localK8sInformerFactory informers.SharedInformerFactory        // for k8s built-in resources local to the node
	crdInformerFactory      externalversions.SharedInformerFactory // for Tetragon CRDs
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
		k8sInformerFactory:      k8sInformerFactory,
		localK8sInformerFactory: localK8sInformerFactory,
		crdInformerFactory:      crdInformerFactory,
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
	if w.k8sInformerFactory != nil {
		w.k8sInformerFactory.Start(wait.NeverStop)
		w.k8sInformerFactory.WaitForCacheSync(wait.NeverStop)
	}
	if w.localK8sInformerFactory != nil {
		w.localK8sInformerFactory.Start(wait.NeverStop)
		w.localK8sInformerFactory.WaitForCacheSync(wait.NeverStop)
	}
	if w.crdInformerFactory != nil {
		w.crdInformerFactory.Start(wait.NeverStop)
		w.crdInformerFactory.WaitForCacheSync(wait.NeverStop)
	}
	for name, informer := range w.informers {
		logger.GetLogger().WithFields(logrus.Fields{
			"informer": name,
			"count":    len(informer.GetStore().ListKeys()),
		}).Info("Initialized informer cache")
	}
}

func (w *K8sWatcher) GetK8sInformerFactory() informers.SharedInformerFactory {
	return w.k8sInformerFactory
}

func (w *K8sWatcher) GetLocalK8sInformerFactory() informers.SharedInformerFactory {
	return w.localK8sInformerFactory
}

func (w *K8sWatcher) GetCRDInformerFactory() externalversions.SharedInformerFactory {
	return w.crdInformerFactory
}
