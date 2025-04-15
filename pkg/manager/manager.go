// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package manager

import (
	"context"
	"sync"

	"github.com/bombsimon/logrusr/v4"
	"github.com/cilium/tetragon/pkg/logger"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
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
	manager ctrlManager.Manager
}

func Get() *ControllerManager {
	initOnce.Do(func() {
		ctrl.SetLogger(logrusr.New(logger.GetLogger()))
		scheme := runtime.NewScheme()
		utilruntime.Must(clientgoscheme.AddToScheme(scheme))
		controllerManager, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{Scheme: scheme})
		if err != nil {
			panic(err)
		}
		manager = &ControllerManager{
			manager: controllerManager,
		}
	})
	return manager
}

func (cm *ControllerManager) Start(ctx context.Context) {
	startOnce.Do(func() {
		go func() {
			if err := cm.manager.Start(ctx); err != nil {
				panic(err)
			}
		}()
		cm.manager.GetCache().WaitForCacheSync(ctx)
	})
}

func (cm *ControllerManager) GetNamespace(name string) (*corev1.Namespace, error) {
	ns := corev1.Namespace{}
	if err := cm.manager.GetCache().Get(context.Background(), types.NamespacedName{Name: name}, &ns); err != nil {
		return nil, err
	}
	return &ns, nil
}

func (cm *ControllerManager) ListNamespaces() ([]corev1.Namespace, error) {
	namespaceList := corev1.NamespaceList{}
	if err := cm.manager.GetCache().List(context.Background(), &namespaceList, &client.ListOptions{}); err != nil {
		return nil, err
	}
	return namespaceList.Items, nil
}
