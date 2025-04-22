// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package manager

import (
	"context"
	"sync"

	"github.com/bombsimon/logrusr/v4"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/cache"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlManager "sigs.k8s.io/controller-runtime/pkg/manager"
)

var (
	initOnce, startOnce sync.Once
	manager             *ControllerManager
)

// ControllerManager is responsible for running controller-runtime controllers,
// and interacting with Kubernetes API server in general. If you need to interact
// with Kubernetes API server, this is the place to start.
type ControllerManager struct {
	Manager ctrlManager.Manager
}

func Get() *ControllerManager {
	initOnce.Do(func() {
		ctrl.SetLogger(logrusr.New(logger.GetLogger()))
		scheme := runtime.NewScheme()
		utilruntime.Must(clientgoscheme.AddToScheme(scheme))
		utilruntime.Must(v1alpha1.AddToScheme(scheme))
		utilruntime.Must(apiextensionsv1.AddToScheme(scheme))
		controllerManager, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{Scheme: scheme})
		if err != nil {
			panic(err)
		}
		manager = &ControllerManager{
			Manager: controllerManager,
		}
	})
	return manager
}

func (cm *ControllerManager) Start(ctx context.Context) {
	startOnce.Do(func() {
		go func() {
			if err := cm.Manager.Start(ctx); err != nil {
				panic(err)
			}
		}()
		cm.Manager.GetCache().WaitForCacheSync(ctx)
	})
}

func (cm *ControllerManager) GetNamespace(name string) (*corev1.Namespace, error) {
	ns := corev1.Namespace{}
	if err := cm.Manager.GetCache().Get(context.Background(), types.NamespacedName{Name: name}, &ns); err != nil {
		return nil, err
	}
	return &ns, nil
}

func (cm *ControllerManager) ListNamespaces() ([]corev1.Namespace, error) {
	namespaceList := corev1.NamespaceList{}
	if err := cm.Manager.GetCache().List(context.Background(), &namespaceList, &client.ListOptions{}); err != nil {
		return nil, err
	}
	return namespaceList.Items, nil
}

func (cm *ControllerManager) WaitCRDs(ctx context.Context, crds map[string]struct{}) error {
	log := logger.GetLogger()
	log.WithField("crds", crds).Info("Waiting for required CRDs")
	var wg sync.WaitGroup
	wg.Add(1)
	crdInformer, err := cm.Manager.GetCache().GetInformer(ctx, &apiextensionsv1.CustomResourceDefinition{})
	if err != nil {
		return err
	}
	_, err = crdInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			crdObject, ok := obj.(*apiextensionsv1.CustomResourceDefinition)
			if !ok {
				log.WithField("obj", obj).Warn("Received an invalid object")
				return
			}
			if _, ok := crds[crdObject.Name]; ok {
				log.WithField("crd", crdObject.Name).Info("Found CRD")
				delete(crds, crdObject.Name)
				if len(crds) == 0 {
					log.Info("Found all the required CRDs")
					wg.Done()
				}
			}
		},
	})
	if err != nil {
		log.WithError(err).Error("failed to add event handler")
		return err
	}
	wg.Wait()
	err = cm.Manager.GetCache().RemoveInformer(ctx, &apiextensionsv1.CustomResourceDefinition{})
	if err != nil {
		log.WithError(err).Warn("failed to remove CRD informer")
	}
	return nil
}
