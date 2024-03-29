// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Code generated by lister-gen. DO NOT EDIT.

package v1alpha1

import (
	v1alpha1 "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// PodInfoLister helps list PodInfo.
// All objects returned here must be treated as read-only.
type PodInfoLister interface {
	// List lists all PodInfo in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1alpha1.PodInfo, err error)
	// PodInfo returns an object that can list and get PodInfo.
	PodInfo(namespace string) PodInfoNamespaceLister
	PodInfoListerExpansion
}

// podInfoLister implements the PodInfoLister interface.
type podInfoLister struct {
	indexer cache.Indexer
}

// NewPodInfoLister returns a new PodInfoLister.
func NewPodInfoLister(indexer cache.Indexer) PodInfoLister {
	return &podInfoLister{indexer: indexer}
}

// List lists all PodInfo in the indexer.
func (s *podInfoLister) List(selector labels.Selector) (ret []*v1alpha1.PodInfo, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1alpha1.PodInfo))
	})
	return ret, err
}

// PodInfo returns an object that can list and get PodInfo.
func (s *podInfoLister) PodInfo(namespace string) PodInfoNamespaceLister {
	return podInfoNamespaceLister{indexer: s.indexer, namespace: namespace}
}

// PodInfoNamespaceLister helps list and get PodInfo.
// All objects returned here must be treated as read-only.
type PodInfoNamespaceLister interface {
	// List lists all PodInfo in the indexer for a given namespace.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1alpha1.PodInfo, err error)
	// Get retrieves the PodInfo from the indexer for a given namespace and name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1alpha1.PodInfo, error)
	PodInfoNamespaceListerExpansion
}

// podInfoNamespaceLister implements the PodInfoNamespaceLister
// interface.
type podInfoNamespaceLister struct {
	indexer   cache.Indexer
	namespace string
}

// List lists all PodInfo in the indexer for a given namespace.
func (s podInfoNamespaceLister) List(selector labels.Selector) (ret []*v1alpha1.PodInfo, err error) {
	err = cache.ListAllByNamespace(s.indexer, s.namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*v1alpha1.PodInfo))
	})
	return ret, err
}

// Get retrieves the PodInfo from the indexer for a given namespace and name.
func (s podInfoNamespaceLister) Get(name string) (*v1alpha1.PodInfo, error) {
	obj, exists, err := s.indexer.GetByKey(s.namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1alpha1.Resource("podinfo"), name)
	}
	return obj.(*v1alpha1.PodInfo), nil
}
