// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !nok8s

package crdwatcher

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

// fakeSensors records calls into sensors.Manager so tests can assert the
// Reconcile decision tree without spinning up the real BPF loader.
type fakeSensors struct {
	addCalls    []addCall
	deleteCalls []deleteCall
	addErr      error
	deleteErr   error
}

type addCall struct {
	name      string
	namespace string
}

type deleteCall struct {
	name      string
	namespace string
}

func (f *fakeSensors) AddTracingPolicy(_ context.Context, tp tracingpolicy.TracingPolicy) error {
	f.addCalls = append(f.addCalls, addCall{tp.TpName(), tp.TpNamespace()})
	return f.addErr
}

func (f *fakeSensors) DeleteTracingPolicy(_ context.Context, name, namespace string) error {
	f.deleteCalls = append(f.deleteCalls, deleteCall{name, namespace})
	return f.deleteErr
}

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(s))
	utilruntime.Must(v1alpha1.AddToScheme(s))
	return s
}

func newPolicy(name string) *v1alpha1.TracingPolicy {
	return &v1alpha1.TracingPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       v1alpha1.TPKindDefinition,
			APIVersion: "cilium.io/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
}

func TestReconcile_NotFound_CallsDelete(t *testing.T) {
	sensors := &fakeSensors{}
	cli := fake.NewClientBuilder().WithScheme(newScheme(t)).Build()
	r := &TracingPolicyReconciler{Client: cli, Sensors: sensors}

	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "missing"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, res)

	require.Len(t, sensors.deleteCalls, 1)
	assert.Equal(t, "missing", sensors.deleteCalls[0].name)
	assert.Empty(t, sensors.deleteCalls[0].namespace, "TP is cluster-scoped")
	assert.Empty(t, sensors.addCalls, "no Add on NotFound")
}

func TestReconcile_Found_CallsDeleteThenAdd(t *testing.T) {
	tp := newPolicy("p1")
	sensors := &fakeSensors{}
	cli := fake.NewClientBuilder().
		WithScheme(newScheme(t)).
		WithObjects(tp).
		Build()
	r := &TracingPolicyReconciler{Client: cli, Sensors: sensors}

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: tp.Name},
	})
	require.NoError(t, err)

	// Delete-before-Add (best-effort cleanup of any stale state) is followed
	// by Add(tp). This is the same pattern as the prior informer's Update
	// path.
	require.Len(t, sensors.deleteCalls, 1)
	assert.Equal(t, "p1", sensors.deleteCalls[0].name)
	require.Len(t, sensors.addCalls, 1)
	assert.Equal(t, "p1", sensors.addCalls[0].name)
}

func TestReconcile_GetError_PropagatesAndDoesNothing(t *testing.T) {
	wantErr := errors.New("boom")
	sensors := &fakeSensors{}
	cli := fake.NewClientBuilder().
		WithScheme(newScheme(t)).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(_ context.Context, _ client.WithWatch, _ client.ObjectKey, _ client.Object, _ ...client.GetOption) error {
				return wantErr
			},
		}).
		Build()
	r := &TracingPolicyReconciler{Client: cli, Sensors: sensors}

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "p1"},
	})
	require.ErrorIs(t, err, wantErr)
	assert.Empty(t, sensors.addCalls)
	assert.Empty(t, sensors.deleteCalls)
}

func TestReconcile_DeleteError_DoesNotBlockAdd(t *testing.T) {
	tp := newPolicy("p1")
	sensors := &fakeSensors{deleteErr: errors.New("not in collection — fine")}
	cli := fake.NewClientBuilder().
		WithScheme(newScheme(t)).
		WithObjects(tp).
		Build()
	r := &TracingPolicyReconciler{Client: cli, Sensors: sensors}

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: tp.Name},
	})
	require.NoError(t, err)
	require.Len(t, sensors.deleteCalls, 1)
	require.Len(t, sensors.addCalls, 1, "delete-before-add error must not skip the Add")
}

// fakeControllerManager records RegisterControllerWhenCRDReady calls to verify
// the wiring helper.
type fakeControllerManager struct {
	gotCRD string
	setup  func(ctrl.Manager) error
}

func (f *fakeControllerManager) RegisterControllerWhenCRDReady(crdName string, setup func(ctrl.Manager) error) error {
	f.gotCRD = crdName
	f.setup = setup
	return nil
}

func TestRegisterTracingPolicyReconciler_GatesOnCorrectCRD(t *testing.T) {
	cm := &fakeControllerManager{}
	require.NoError(t, RegisterTracingPolicyReconciler(cm, &fakeSensors{}))
	assert.Equal(t, v1alpha1.TPName, cm.gotCRD)
	assert.NotNil(t, cm.setup, "setup callback must be wired")
}
