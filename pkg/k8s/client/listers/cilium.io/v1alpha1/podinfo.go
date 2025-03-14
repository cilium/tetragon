// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Code generated by lister-gen. DO NOT EDIT.

package v1alpha1

import (
	ciliumiov1alpha1 "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	labels "k8s.io/apimachinery/pkg/labels"
	listers "k8s.io/client-go/listers"
	cache "k8s.io/client-go/tools/cache"
)

// PodInfoLister helps list PodInfo.
// All objects returned here must be treated as read-only.
type PodInfoLister interface {
	// List lists all PodInfo in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*ciliumiov1alpha1.PodInfo, err error)
	// PodInfo returns an object that can list and get PodInfo.
	PodInfo(namespace string) PodInfoNamespaceLister
	PodInfoListerExpansion
}

// podInfoLister implements the PodInfoLister interface.
type podInfoLister struct {
	listers.ResourceIndexer[*ciliumiov1alpha1.PodInfo]
}

// NewPodInfoLister returns a new PodInfoLister.
func NewPodInfoLister(indexer cache.Indexer) PodInfoLister {
	return &podInfoLister{listers.New[*ciliumiov1alpha1.PodInfo](indexer, ciliumiov1alpha1.Resource("podinfo"))}
}

// PodInfo returns an object that can list and get PodInfo.
func (s *podInfoLister) PodInfo(namespace string) PodInfoNamespaceLister {
	return podInfoNamespaceLister{listers.NewNamespaced[*ciliumiov1alpha1.PodInfo](s.ResourceIndexer, namespace)}
}

// PodInfoNamespaceLister helps list and get PodInfo.
// All objects returned here must be treated as read-only.
type PodInfoNamespaceLister interface {
	// List lists all PodInfo in the indexer for a given namespace.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*ciliumiov1alpha1.PodInfo, err error)
	// Get retrieves the PodInfo from the indexer for a given namespace and name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*ciliumiov1alpha1.PodInfo, error)
	PodInfoNamespaceListerExpansion
}

// podInfoNamespaceLister implements the PodInfoNamespaceLister
// interface.
type podInfoNamespaceLister struct {
	listers.ResourceIndexer[*ciliumiov1alpha1.PodInfo]
}
