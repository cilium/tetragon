// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"

	v1alpha1 "github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
)

// FakeTracingPolicies implements TracingPolicyInterface
type FakeTracingPolicies struct {
	Fake *FakeCiliumV1alpha1
}

var tracingpoliciesResource = v1alpha1.SchemeGroupVersion.WithResource("tracingpolicies")

var tracingpoliciesKind = v1alpha1.SchemeGroupVersion.WithKind("TracingPolicy")

// Get takes name of the tracingPolicy, and returns the corresponding tracingPolicy object, and an error if there is any.
func (c *FakeTracingPolicies) Get(ctx context.Context, name string, options v1.GetOptions) (result *v1alpha1.TracingPolicy, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootGetAction(tracingpoliciesResource, name), &v1alpha1.TracingPolicy{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.TracingPolicy), err
}

// List takes label and field selectors, and returns the list of TracingPolicies that match those selectors.
func (c *FakeTracingPolicies) List(ctx context.Context, opts v1.ListOptions) (result *v1alpha1.TracingPolicyList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootListAction(tracingpoliciesResource, tracingpoliciesKind, opts), &v1alpha1.TracingPolicyList{})
	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v1alpha1.TracingPolicyList{ListMeta: obj.(*v1alpha1.TracingPolicyList).ListMeta}
	for _, item := range obj.(*v1alpha1.TracingPolicyList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested tracingPolicies.
func (c *FakeTracingPolicies) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchAction(tracingpoliciesResource, opts))
}

// Create takes the representation of a tracingPolicy and creates it.  Returns the server's representation of the tracingPolicy, and an error, if there is any.
func (c *FakeTracingPolicies) Create(ctx context.Context, tracingPolicy *v1alpha1.TracingPolicy, opts v1.CreateOptions) (result *v1alpha1.TracingPolicy, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateAction(tracingpoliciesResource, tracingPolicy), &v1alpha1.TracingPolicy{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.TracingPolicy), err
}

// Update takes the representation of a tracingPolicy and updates it. Returns the server's representation of the tracingPolicy, and an error, if there is any.
func (c *FakeTracingPolicies) Update(ctx context.Context, tracingPolicy *v1alpha1.TracingPolicy, opts v1.UpdateOptions) (result *v1alpha1.TracingPolicy, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateAction(tracingpoliciesResource, tracingPolicy), &v1alpha1.TracingPolicy{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.TracingPolicy), err
}

// Delete takes name of the tracingPolicy and deletes it. Returns an error if one occurs.
func (c *FakeTracingPolicies) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteActionWithOptions(tracingpoliciesResource, name, opts), &v1alpha1.TracingPolicy{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeTracingPolicies) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewRootDeleteCollectionAction(tracingpoliciesResource, listOpts)

	_, err := c.Fake.Invokes(action, &v1alpha1.TracingPolicyList{})
	return err
}

// Patch applies the patch and returns the patched tracingPolicy.
func (c *FakeTracingPolicies) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v1alpha1.TracingPolicy, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(tracingpoliciesResource, name, pt, data, subresources...), &v1alpha1.TracingPolicy{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v1alpha1.TracingPolicy), err
}
