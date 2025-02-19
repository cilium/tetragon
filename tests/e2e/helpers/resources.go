// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package helpers

import (
	"context"
	"os"
	"strings"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog/v2"
	"sigs.k8s.io/e2e-framework/klient/decoder"
	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/wait"
	"sigs.k8s.io/e2e-framework/klient/wait/conditions"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/envfuncs"
)

// NewObjectList creates a new k8s.ObjectList from a list of k8s.Object
func NewObjectList(objs []k8s.Object) k8s.ObjectList {
	list := &metav1.List{}
	for _, obj := range objs {
		list.Items = append(list.Items, runtime.RawExtension{
			Object: obj,
		})
	}
	return list
}

// CreateNamespace is a wrapper around envfuncs.CreateNamespace with optional support to
// wait for namespace creation.
func CreateNamespace(namespace string, waitForCreation bool) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		client, err := cfg.NewClient()
		if err != nil {
			return ctx, err
		}
		r := client.Resources(namespace)

		ctx, err = envfuncs.CreateNamespace(namespace)(ctx, cfg)
		if err != nil {
			return ctx, err
		}

		if waitForCreation {
			klog.InfoS("Waiting for namespace to be created...", "namespace", namespace)
			ns := &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
			wait.For(conditions.New(r).ResourceMatch(ns, func(_ k8s.Object) bool {
				return true
			}))
		}
		klog.InfoS("Created new namespace", "namespace", namespace)

		return ctx, nil
	}
}

// DeleteNamespace is a wrapper around envfuncs.DeleteNamespace with optional support to
// wait for namespace deletion.
func DeleteNamespace(namespace string, waitForDeletion bool) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		client, err := cfg.NewClient()
		if err != nil {
			return ctx, err
		}
		r := client.Resources(namespace)

		ctx, err = envfuncs.DeleteNamespace(namespace)(ctx, cfg)
		if err != nil {
			return ctx, err
		}

		if waitForDeletion {
			ns := &v1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}
			wait.For(conditions.New(r).ResourceDeleted(ns))
		}

		return ctx, nil
	}
}

// LoadObjects loads a list of k8s.Object and optionally waits for all resources to be
// created and pods to be ready.
func LoadObjects(namespace string, objs []k8s.Object, waitForPods bool) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		client, err := cfg.NewClient()
		if err != nil {
			return ctx, err
		}
		r := client.Resources(namespace)

		for _, obj := range objs {
			obj.SetNamespace(namespace)
			if err := r.Create(ctx, obj); err != nil {
				return ctx, err
			}
			klog.V(2).InfoS("Created resource", "namespace", namespace, "name", obj.GetName(), "kind", obj.GetObjectKind().GroupVersionKind().Kind)
		}

		if waitForPods {
			// Wait for resources to be created
			klog.Infof("Waiting for resource creation...")
			list := NewObjectList(objs)
			wait.For(conditions.New(r).ResourcesFound(list))

			// Wait for pods in the namespace to be ready
			klog.Infof("Waiting for pods in %s to be ready...", namespace)
			podList := &v1.PodList{}
			r.List(ctx, podList)
			wait.For(conditions.New(r).ResourcesMatch(podList, func(object k8s.Object) bool {
				o := object.(*v1.Pod)
				return o.Status.Phase == v1.PodRunning || o.Status.Phase == v1.PodSucceeded
			}))

			klog.Infof("Resources created and all pods in %s ready!", namespace)
		}

		return ctx, nil
	}
}

// LoadCRDFile decodes a CRD file and calls LoadObjects on the result.
func LoadCRDFile(namespace string, file string, waitForPods bool) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		f, err := os.Open(file)
		if err != nil {
			return ctx, err
		}

		objs, err := decoder.DecodeAll(ctx, f)
		if err != nil {
			return ctx, err
		}

		return LoadObjects(namespace, objs, waitForPods)(ctx, cfg)
	}
}

// LoadCRDString decodes a CRD from a yaml string and calls LoadObjects on the result.
func LoadCRDString(namespace string, yamlStr string, waitForPods bool) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		f := strings.NewReader(yamlStr)

		objs, err := decoder.DecodeAll(ctx, f)
		if err != nil {
			return ctx, err
		}

		return LoadObjects(namespace, objs, waitForPods)(ctx, cfg)
	}
}

// UnloadObjects unloads a list of k8s.Object and optionally waits for all resources to be
// deleted.
func UnloadObjects(namespace string, objs []k8s.Object, waitForDeletion bool) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		client, err := cfg.NewClient()
		if err != nil {
			return ctx, err
		}
		r := client.Resources(namespace)

		for _, obj := range objs {
			obj.SetNamespace(namespace)
			if err := r.Delete(ctx, obj); err != nil {
				return ctx, err
			}
			klog.V(2).InfoS("Deleted resource", "namespace", namespace, "name", obj.GetName(), "kind", obj.GetObjectKind().GroupVersionKind().Kind)
		}

		if waitForDeletion {
			// Wait for resources to be created
			klog.Infof("Waiting for resource deletion...")
			list := NewObjectList(objs)
			wait.For(conditions.New(r).ResourcesDeleted(list))
			klog.Infof("Resources deleted!")
		}

		return ctx, nil
	}
}

// UnloadCRDFile decodes a CRD file and calls UnloadObjects on the result.
func UnloadCRDFile(namespace string, file string, waitForDeletion bool) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		f, err := os.Open(file)
		if err != nil {
			return ctx, err
		}

		objs, err := decoder.DecodeAll(ctx, f)
		if err != nil {
			return ctx, err
		}

		return UnloadObjects(namespace, objs, waitForDeletion)(ctx, cfg)
	}
}

// UnloadCRDString decodes a CRD yaml string and calls UnloadObjects on the result.
func UnloadCRDString(namespace string, yamlStr string, waitForDeletion bool) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		f := strings.NewReader(yamlStr)

		objs, err := decoder.DecodeAll(ctx, f)
		if err != nil {
			return ctx, err
		}

		return UnloadObjects(namespace, objs, waitForDeletion)(ctx, cfg)
	}
}
