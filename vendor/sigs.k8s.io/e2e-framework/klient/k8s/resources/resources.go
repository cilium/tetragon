/*
Copyright 2021 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package resources

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	klog "k8s.io/klog/v2"
	cr "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"sigs.k8s.io/e2e-framework/klient/k8s"
	"sigs.k8s.io/e2e-framework/klient/k8s/watcher"
)

type Resources struct {
	// config is the rest.Config to talk to an apiserver
	config *rest.Config

	// scheme will be used to map go structs to GroupVersionKinds
	scheme *runtime.Scheme

	// client is a wrapper for controller runtime client
	client cr.Client

	// namespace for namespaced object requests
	namespace string
}

// New instantiates the controller runtime client
// object. User can get panic for belopw scenarios.
// 1. if user does not provide k8s config
// 2. if controller runtime client instantiation fails.
func New(cfg *rest.Config) (*Resources, error) {
	if cfg == nil {
		return nil, errors.New("must provide rest.Config")
	}

	cl, err := cr.New(cfg, cr.Options{Scheme: scheme.Scheme})
	if err != nil {
		return nil, err
	}

	res := &Resources{
		config: cfg,
		scheme: scheme.Scheme,
		client: cl,
	}

	return res, nil
}

// GetConfig hepls to get config type *rest.Config
func (r *Resources) GetConfig() *rest.Config {
	return r.config
}

func (r *Resources) WithNamespace(ns string) *Resources {
	r.namespace = ns
	return r
}

func (r *Resources) Get(ctx context.Context, name, namespace string, obj k8s.Object) error {
	return r.client.Get(ctx, cr.ObjectKey{Namespace: namespace, Name: name}, obj)
}

type CreateOption func(*metav1.CreateOptions)

func (r *Resources) Create(ctx context.Context, obj k8s.Object, opts ...CreateOption) error {
	createOptions := &metav1.CreateOptions{}
	for _, fn := range opts {
		fn(createOptions)
	}

	o := &cr.CreateOptions{
		Raw:          createOptions,
		DryRun:       createOptions.DryRun,
		FieldManager: createOptions.FieldManager,
	}

	return r.client.Create(ctx, obj, o)
}

type UpdateOption func(*metav1.UpdateOptions)

func (r *Resources) Update(ctx context.Context, obj k8s.Object, opts ...UpdateOption) error {
	updateOptions := &metav1.UpdateOptions{}
	for _, fn := range opts {
		fn(updateOptions)
	}

	o := &cr.UpdateOptions{
		Raw:          updateOptions,
		DryRun:       updateOptions.DryRun,
		FieldManager: updateOptions.FieldManager,
	}
	return r.client.Update(ctx, obj, o)
}

// UpdateSubresource updates the subresource of the object
func (r *Resources) UpdateSubresource(ctx context.Context, obj k8s.Object, subresource string, opts ...UpdateOption) error {
	updateOptions := &metav1.UpdateOptions{}
	for _, fn := range opts {
		fn(updateOptions)
	}

	uo := cr.UpdateOptions{Raw: updateOptions}
	o := &cr.SubResourceUpdateOptions{UpdateOptions: uo}
	return r.client.SubResource(subresource).Update(ctx, obj, o)
}

// UpdateStatus updates the status of the object
func (r *Resources) UpdateStatus(ctx context.Context, obj k8s.Object, opts ...UpdateOption) error {
	return r.UpdateSubresource(ctx, obj, "status", opts...)
}

type DeleteOption func(*metav1.DeleteOptions)

func (r *Resources) Delete(ctx context.Context, obj k8s.Object, opts ...DeleteOption) error {
	deleteOptions := &metav1.DeleteOptions{}
	for _, fn := range opts {
		fn(deleteOptions)
	}

	o := &cr.DeleteOptions{
		Raw:                deleteOptions,
		GracePeriodSeconds: deleteOptions.GracePeriodSeconds,
		Preconditions:      deleteOptions.Preconditions,
		PropagationPolicy:  deleteOptions.PropagationPolicy,
		DryRun:             deleteOptions.DryRun,
	}
	return r.client.Delete(ctx, obj, o)
}

func WithGracePeriod(gpt time.Duration) DeleteOption {
	t := int64(gpt.Seconds())
	return func(do *metav1.DeleteOptions) { do.GracePeriodSeconds = &t }
}

func WithDeletePropagation(prop string) DeleteOption {
	p := metav1.DeletionPropagation(prop)
	return func(do *metav1.DeleteOptions) { do.PropagationPolicy = &p }
}

type ListOption func(*metav1.ListOptions)

func (r *Resources) List(ctx context.Context, objs k8s.ObjectList, opts ...ListOption) error {
	listOptions := &metav1.ListOptions{}

	for _, fn := range opts {
		fn(listOptions)
	}

	ls, err := labels.Parse(listOptions.LabelSelector)
	if err != nil {
		return err
	}
	fs, err := fields.ParseSelector(listOptions.FieldSelector)
	if err != nil {
		return err
	}

	o := &cr.ListOptions{
		Raw:           listOptions,
		FieldSelector: fs,
		LabelSelector: ls,
		Continue:      listOptions.Continue,
		Limit:         listOptions.Limit,
	}
	if r.namespace != "" {
		o.Namespace = r.namespace
	}

	return r.client.List(ctx, objs, o)
}

func WithLabelSelector(sel string) ListOption {
	return func(lo *metav1.ListOptions) { lo.LabelSelector = sel }
}

func WithFieldSelector(sel string) ListOption {
	return func(lo *metav1.ListOptions) { lo.FieldSelector = sel }
}

func WithTimeout(to time.Duration) ListOption {
	t := int64(to.Seconds())
	return func(lo *metav1.ListOptions) { lo.TimeoutSeconds = &t }
}

// PatchOption is used to provide additional arguments to the Patch call.
type PatchOption func(*metav1.PatchOptions)

// Patch patches portion of object `obj` with data from object `patch`
func (r *Resources) Patch(ctx context.Context, obj k8s.Object, patch k8s.Patch, opts ...PatchOption) error {
	patchOptions := &metav1.PatchOptions{}

	for _, fn := range opts {
		fn(patchOptions)
	}

	p := cr.RawPatch(patch.PatchType, patch.Data)

	o := &cr.PatchOptions{
		Raw:          patchOptions,
		DryRun:       patchOptions.DryRun,
		Force:        patchOptions.Force,
		FieldManager: patchOptions.FieldManager,
	}
	return r.client.Patch(ctx, obj, p, o)
}

// PatchSubresource patches portion of object `obj` with data from object `patch`
func (r *Resources) PatchSubresource(ctx context.Context, obj k8s.Object, subresource string, patch k8s.Patch, opts ...PatchOption) error {
	patchOptions := &metav1.PatchOptions{}

	for _, fn := range opts {
		fn(patchOptions)
	}

	p := cr.RawPatch(patch.PatchType, patch.Data)

	po := cr.PatchOptions{Raw: patchOptions}
	o := &cr.SubResourcePatchOptions{PatchOptions: po}
	return r.client.SubResource(subresource).Patch(ctx, obj, p, o)
}

// PatchStatus patches portion of object `obj` with data from object `patch`
func (r *Resources) PatchStatus(ctx context.Context, objs k8s.Object, patch k8s.Patch, opts ...PatchOption) error {
	return r.PatchSubresource(ctx, objs, "status", patch, opts...)
}

// Annotate attach annotations to an existing resource objec
func (r *Resources) Annotate(obj k8s.Object, annotation map[string]string) {
	obj.SetAnnotations(annotation)
}

// Label apply labels to an existing resources.
func (r *Resources) Label(obj k8s.Object, label map[string]string) {
	obj.SetLabels(label)
}

func (r *Resources) GetScheme() *runtime.Scheme {
	return r.scheme
}

// GetControllerRuntimeClient return the controller-runtime client instance
func (r *Resources) GetControllerRuntimeClient() cr.Client {
	return r.client
}

func (r *Resources) Watch(object k8s.ObjectList, opts ...ListOption) *watcher.EventHandlerFuncs {
	listOptions := &metav1.ListOptions{}

	for _, fn := range opts {
		fn(listOptions)
	}

	o := &cr.ListOptions{Raw: listOptions}

	return &watcher.EventHandlerFuncs{
		ListOptions: o,
		K8sObject:   object,
		Cfg:         r.GetConfig(),
	}
}

func (r *Resources) ExecInPod(ctx context.Context, namespaceName, podName, containerName string, command []string, stdout, stderr *bytes.Buffer) error {
	clientset, err := kubernetes.NewForConfig(r.config)
	if err != nil {
		return err
	}

	req := clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace(namespaceName).
		SubResource("exec")
	newScheme := runtime.NewScheme()
	if err := v1.AddToScheme(newScheme); err != nil {
		return err
	}
	parameterCodec := runtime.NewParameterCodec(newScheme)
	req.VersionedParams(&v1.PodExecOptions{
		Container: containerName,
		Command:   command,
		Stdout:    true,
		Stderr:    true,
	}, parameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(r.config, "POST", req.URL())
	if err != nil {
		panic(err)
	}

	err = exec.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: stdout,
		Stderr: stderr,
	})
	if err != nil {
		return err
	}

	return nil
}

type matcher[T any] func([]T) (T, error)

type predicate[T any] func(T) bool

func match[T any](pred predicate[T], err error) matcher[T] {
	return func(values []T) (T, error) {
		for _, value := range values {
			if pred(value) {
				return value, nil
			}
		}

		var notFound T
		return notFound, err
	}
}

func matchByIndex[T any](idx int, err error) matcher[T] {
	return func(items []T) (T, error) {
		if idx >= len(items) {
			var notFound T
			return notFound, fmt.Errorf("%w: index %d is out of range with length %d", err, idx, len(items))
		}

		return items[idx], nil
	}
}

var (
	errPodNotFound       = errors.New("pod not found")
	errContainerNotFound = errors.New("container not found")
)

type deploymentOptions struct {
	podMatcher       matcher[v1.Pod]
	containerMatcher matcher[v1.Container]
}

// DeploymentOption extends the default behavior of [ExecInDeployment].
type DeploymentOption func(*deploymentOptions)

// WithDeploymentPod selects the pod that matches the given condition.
func WithDeploymentPod(pred predicate[v1.Pod]) DeploymentOption {
	return func(opts *deploymentOptions) {
		opts.podMatcher = match(pred, errPodNotFound)
	}
}

// WithDeploymentPodIndex selects the pod at the given index.
func WithDeploymentPodIndex(idx int) DeploymentOption {
	return func(opts *deploymentOptions) {
		opts.podMatcher = matchByIndex[v1.Pod](idx, errPodNotFound)
	}
}

// WithDeploymentContainer selects the container that matches the given condition.
func WithDeploymentContainer(pred predicate[v1.Container]) DeploymentOption {
	return func(opts *deploymentOptions) {
		opts.containerMatcher = match(pred, errContainerNotFound)
	}
}

// WithDeploymentContainerIndex selects the container at the given index.
func WithDeploymentContainerIndex(idx int) DeploymentOption {
	return func(opts *deploymentOptions) {
		opts.containerMatcher = matchByIndex[v1.Container](idx, errContainerNotFound)
	}
}

// WithDeploymentContainerName selects the container with the given name.
func WithDeploymentContainerName(name string) DeploymentOption {
	return func(opts *deploymentOptions) {
		opts.containerMatcher = match(
			func(c v1.Container) bool { return c.Name == name },
			fmt.Errorf("%w: name %q", errContainerNotFound, name),
		)
	}
}

// ExecInDeployment runs the given command in a container belonging to the deployment with the given name.
// By default, it selects the first container of the first pod.
//
// Pod and container selection can be customized using [WithDeploymentPod], [WithDeploymentContainer],
// or related functions.
func (r *Resources) ExecInDeployment(ctx context.Context, namespaceName, deploymentName string, command []string, stdout, stderr *bytes.Buffer, opts ...DeploymentOption) error {
	options := deploymentOptions{}
	defaultOpts := []DeploymentOption{WithDeploymentPodIndex(0), WithDeploymentContainerIndex(0)}
	for _, fn := range append(defaultOpts, opts...) {
		fn(&options)
	}

	var deployment appsv1.Deployment
	if err := r.Get(ctx, deploymentName, namespaceName, &deployment); err != nil {
		return err
	}

	sel, err := metav1.LabelSelectorAsSelector(deployment.Spec.Selector)
	if err != nil {
		return err
	}

	var pods v1.PodList
	if err := r.client.List(ctx, &pods, cr.InNamespace(namespaceName), cr.MatchingLabelsSelector{Selector: sel}); err != nil {
		return err
	}

	pod, err := options.podMatcher(pods.Items)
	if err != nil {
		return err
	}

	container, err := options.containerMatcher(pod.Spec.Containers)
	if err != nil {
		return err
	}

	return r.ExecInPod(ctx, namespaceName, pod.Name, container.Name, command, stdout, stderr)
}

func init() {
	log.SetLogger(klog.NewKlogr())
}
