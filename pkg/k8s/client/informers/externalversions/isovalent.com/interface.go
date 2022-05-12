// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Code generated by informer-gen. DO NOT EDIT.

package isovalent

import (
	internalinterfaces "github.com/cilium/tetragon/pkg/k8s/client/informers/externalversions/internalinterfaces"
	v1alpha1 "github.com/cilium/tetragon/pkg/k8s/client/informers/externalversions/isovalent.com/v1alpha1"
)

// Interface provides access to each of this group's versions.
type Interface interface {
	// V1alpha1 provides access to shared informers for resources in V1alpha1.
	V1alpha1() v1alpha1.Interface
}

type group struct {
	factory          internalinterfaces.SharedInformerFactory
	namespace        string
	tweakListOptions internalinterfaces.TweakListOptionsFunc
}

// New returns a new Interface.
func New(f internalinterfaces.SharedInformerFactory, namespace string, tweakListOptions internalinterfaces.TweakListOptionsFunc) Interface {
	return &group{factory: f, namespace: namespace, tweakListOptions: tweakListOptions}
}

// V1alpha1 returns a new v1alpha1.Interface.
func (g *group) V1alpha1() v1alpha1.Interface {
	return v1alpha1.New(g.factory, g.namespace, g.tweakListOptions)
}
