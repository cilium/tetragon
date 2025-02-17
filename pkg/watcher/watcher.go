// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package watcher

import (
	"fmt"
	"reflect"
	"time"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/podhooks"
	"github.com/cilium/tetragon/pkg/reader/node"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

type Watcher interface {
	AddInformers(factory InternalSharedInformerFactory, infs ...*InternalInformer)
	GetInformer(name string) cache.SharedIndexInformer
	Start()
}

type K8sWatcher struct {
	informers       map[string]cache.SharedIndexInformer
	startFunc       func()
	deletedPodCache *deletedPodCache
}

type InternalSharedInformerFactory interface {
	Start(stopCh <-chan struct{})
	WaitForCacheSync(stopCh <-chan struct{}) map[reflect.Type]bool
}

type InternalInformer struct {
	Name     string
	Informer cache.SharedIndexInformer
	Indexers cache.Indexers
}

func newK8sWatcher(
	informerFactory informers.SharedInformerFactory,
) (*K8sWatcher, error) {

	deletedPodCache, err := newDeletedPodCache()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize deleted pod cache: %w", err)
	}

	k8sWatcher := &K8sWatcher{
		informers:       make(map[string]cache.SharedIndexInformer),
		startFunc:       func() {},
		deletedPodCache: deletedPodCache,
	}

	podInformer := informerFactory.Core().V1().Pods().Informer()
	k8sWatcher.AddInformers(informerFactory, &InternalInformer{
		Name:     podInformerName,
		Informer: podInformer,
		Indexers: map[string]cache.IndexFunc{
			containerIdx: containerIndexFunc,
			podIdx:       podIndexFunc,
		},
	})
	podInformer.AddEventHandler(k8sWatcher.deletedPodCache.eventHandler())
	podhooks.InstallHooks(podInformer)

	return k8sWatcher, nil
}

// NewK8sWatcher returns a pointer to an initialized K8sWatcher struct.
func NewK8sWatcher(k8sClient kubernetes.Interface, stateSyncIntervalSec time.Duration) (*K8sWatcher, error) {
	nodeName := node.GetNodeNameForExport()
	if nodeName == "" {
		logger.GetLogger().Warn("env var NODE_NAME not specified, K8s watcher will not work as expected")
	}

	informerFactory := informers.NewSharedInformerFactoryWithOptions(k8sClient, stateSyncIntervalSec,
		informers.WithTweakListOptions(func(options *metav1.ListOptions) {
			// Watch local pods only.
			options.FieldSelector = "spec.nodeName=" + nodeName
		}))

	return newK8sWatcher(informerFactory)
}

func (watcher *K8sWatcher) AddInformers(factory InternalSharedInformerFactory, infs ...*InternalInformer) {
	if watcher.startFunc == nil {
		watcher.startFunc = func() {}
	}
	// Add informers
	for _, inf := range infs {
		watcher.informers[inf.Name] = inf.Informer
		oldStart := watcher.startFunc
		watcher.startFunc = func() {
			oldStart()
			err := inf.Informer.AddIndexers(inf.Indexers)
			if err != nil {
				// Panic during setup since this should never fail, if it fails is a
				// developer mistake.
				panic(err)
			}
		}
	}
	// Start the informer factory
	oldStart := watcher.startFunc
	watcher.startFunc = func() {
		oldStart()
		factory.Start(wait.NeverStop)
		factory.WaitForCacheSync(wait.NeverStop)
		for name, informer := range watcher.informers {
			logger.GetLogger().WithField("informer", name).WithField("count", len(informer.GetStore().ListKeys())).Info("Initialized informer cache")
		}
	}
}

func (watcher *K8sWatcher) GetInformer(name string) cache.SharedIndexInformer {
	return watcher.informers[name]
}

func (watcher *K8sWatcher) Start() {
	if watcher.startFunc != nil {
		watcher.startFunc()
	}
}
