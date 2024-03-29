// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	"context"
	"time"

	v1alpha1 "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	scheme "github.com/cilium/tetragon/pkg/k8s/client/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// TracingPoliciesNamespacedGetter has a method to return a TracingPolicyNamespacedInterface.
// A group's client should implement this interface.
type TracingPoliciesNamespacedGetter interface {
	TracingPoliciesNamespaced(namespace string) TracingPolicyNamespacedInterface
}

// TracingPolicyNamespacedInterface has methods to work with TracingPolicyNamespaced resources.
type TracingPolicyNamespacedInterface interface {
	Create(ctx context.Context, tracingPolicyNamespaced *v1alpha1.TracingPolicyNamespaced, opts v1.CreateOptions) (*v1alpha1.TracingPolicyNamespaced, error)
	Update(ctx context.Context, tracingPolicyNamespaced *v1alpha1.TracingPolicyNamespaced, opts v1.UpdateOptions) (*v1alpha1.TracingPolicyNamespaced, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*v1alpha1.TracingPolicyNamespaced, error)
	List(ctx context.Context, opts v1.ListOptions) (*v1alpha1.TracingPolicyNamespacedList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.TracingPolicyNamespaced, err error)
	TracingPolicyNamespacedExpansion
}

// tracingPoliciesNamespaced implements TracingPolicyNamespacedInterface
type tracingPoliciesNamespaced struct {
	client rest.Interface
	ns     string
}

// newTracingPoliciesNamespaced returns a TracingPoliciesNamespaced
func newTracingPoliciesNamespaced(c *CiliumV1alpha1Client, namespace string) *tracingPoliciesNamespaced {
	return &tracingPoliciesNamespaced{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the tracingPolicyNamespaced, and returns the corresponding tracingPolicyNamespaced object, and an error if there is any.
func (c *tracingPoliciesNamespaced) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.TracingPolicyNamespaced, err error) {
	result = &v1alpha1.TracingPolicyNamespaced{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("tracingpoliciesnamespaced").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do(ctx).
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of TracingPoliciesNamespaced that match those selectors.
func (c *tracingPoliciesNamespaced) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.TracingPolicyNamespacedList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha1.TracingPolicyNamespacedList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("tracingpoliciesnamespaced").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do(ctx).
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested tracingPoliciesNamespaced.
func (c *tracingPoliciesNamespaced) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("tracingpoliciesnamespaced").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch(ctx)
}

// Create takes the representation of a tracingPolicyNamespaced and creates it.  Returns the server's representation of the tracingPolicyNamespaced, and an error, if there is any.
func (c *tracingPoliciesNamespaced) Create(ctx context.Context, tracingPolicyNamespaced *v1alpha1.TracingPolicyNamespaced, opts v1.CreateOptions) (result *v1alpha1.TracingPolicyNamespaced, err error) {
	result = &v1alpha1.TracingPolicyNamespaced{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("tracingpoliciesnamespaced").
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(tracingPolicyNamespaced).
		Do(ctx).
		Into(result)
	return
}

// Update takes the representation of a tracingPolicyNamespaced and updates it. Returns the server's representation of the tracingPolicyNamespaced, and an error, if there is any.
func (c *tracingPoliciesNamespaced) Update(ctx context.Context, tracingPolicyNamespaced *v1alpha1.TracingPolicyNamespaced, opts v1.UpdateOptions) (result *v1alpha1.TracingPolicyNamespaced, err error) {
	result = &v1alpha1.TracingPolicyNamespaced{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("tracingpoliciesnamespaced").
		Name(tracingPolicyNamespaced.Name).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(tracingPolicyNamespaced).
		Do(ctx).
		Into(result)
	return
}

// Delete takes name of the tracingPolicyNamespaced and deletes it. Returns an error if one occurs.
func (c *tracingPoliciesNamespaced) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("tracingpoliciesnamespaced").
		Name(name).
		Body(&opts).
		Do(ctx).
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *tracingPoliciesNamespaced) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	var timeout time.Duration
	if listOpts.TimeoutSeconds != nil {
		timeout = time.Duration(*listOpts.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Namespace(c.ns).
		Resource("tracingpoliciesnamespaced").
		VersionedParams(&listOpts, scheme.ParameterCodec).
		Timeout(timeout).
		Body(&opts).
		Do(ctx).
		Error()
}

// Patch applies the patch and returns the patched tracingPolicyNamespaced.
func (c *tracingPoliciesNamespaced) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.TracingPolicyNamespaced, err error) {
	result = &v1alpha1.TracingPolicyNamespaced{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("tracingpoliciesnamespaced").
		Name(name).
		SubResource(subresources...).
		VersionedParams(&opts, scheme.ParameterCodec).
		Body(data).
		Do(ctx).
		Into(result)
	return
}
