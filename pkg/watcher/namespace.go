// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package watcher

import (
	"errors"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"
)

const (
	namespaceInformerName = "namespace"
)

func AddNamespaceInformer(w Watcher) error {
	if w == nil {
		return errors.New("k8s watcher not initialized")
	}
	factory := w.GetK8sInformerFactory()
	if factory == nil {
		return errors.New("k8s informer factory not initialized")
	}
	informer := factory.Core().V1().Namespaces().Informer()
	w.AddInformer(namespaceInformerName, informer, map[string]cache.IndexFunc{})
	return nil
}

func (watcher *K8sWatcher) GetNamespace(name string) (*corev1.Namespace, error) {
	namespaceInformer := watcher.GetInformer(namespaceInformerName)
	if namespaceInformer == nil {
		return nil, errors.New("namespace informer not initialized")
	}
	obj, exists, err := namespaceInformer.GetStore().GetByKey(name)
	if err != nil {
		return nil, fmt.Errorf("namespace watcher returned: %w", err)
	}
	if !exists {
		return nil, fmt.Errorf("namespace %s not found", name)
	}
	namespace, ok := obj.(*corev1.Namespace)
	if !ok {
		return nil, fmt.Errorf("unexpected type %t", obj)
	}
	return namespace, nil
}
