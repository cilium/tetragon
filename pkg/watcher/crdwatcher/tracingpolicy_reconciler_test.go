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
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

// The tests in this file unit-test the Reconcile decision tree of both
// TracingPolicy Reconcilers without an apiserver: a fake controller-runtime
// client supplies (or fails) the Get, and a fakeSensors recorder captures the
// resulting AddTracingPolicy/DeleteTracingPolicy calls. Every test is
// table-driven over reconcilerKinds() so the cluster-scoped and namespaced
// kinds share same code.

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

func (f *fakeSensors) DeleteTracingPolicy(_ context.Context, name, namespace, _ string) error {
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

type reconcilerKind struct {
	name              string
	crdName           string
	newObject         func(name string) client.Object
	request           ctrl.Request
	expectedNamespace string
	newReconciler     func(client.Client, sensorManager) reconcile.Reconciler
	register          func(controllerManager, sensorManager) error
}

func reconcilerKinds() []reconcilerKind {
	return []reconcilerKind{
		{
			name:    "cluster_scoped",
			crdName: v1alpha1.TPName,
			newObject: func(name string) client.Object {
				return &v1alpha1.TracingPolicy{
					TypeMeta: metav1.TypeMeta{
						Kind:       v1alpha1.TPKindDefinition,
						APIVersion: "cilium.io/v1alpha1",
					},
					ObjectMeta: metav1.ObjectMeta{Name: name},
				}
			},
			request:           ctrl.Request{NamespacedName: types.NamespacedName{Name: "p1"}},
			expectedNamespace: "",
			newReconciler: func(cli client.Client, s sensorManager) reconcile.Reconciler {
				return &TracingPolicyReconciler{Client: cli, Sensors: s}
			},
			register: RegisterTracingPolicyReconciler,
		},
		{
			name:    "namespaced",
			crdName: v1alpha1.TPNamespacedName,
			newObject: func(name string) client.Object {
				return &v1alpha1.TracingPolicyNamespaced{
					TypeMeta: metav1.TypeMeta{
						Kind:       v1alpha1.TPNamespacedKindDefinition,
						APIVersion: "cilium.io/v1alpha1",
					},
					ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "team-a"},
				}
			},
			request:           ctrl.Request{NamespacedName: types.NamespacedName{Name: "p1", Namespace: "team-a"}},
			expectedNamespace: "team-a",
			newReconciler: func(cli client.Client, s sensorManager) reconcile.Reconciler {
				return &TracingPolicyNamespacedReconciler{Client: cli, Sensors: s}
			},
			register: RegisterTracingPolicyNamespacedReconciler,
		},
	}
}

func TestReconcile_NotFound_CallsDelete(t *testing.T) {
	for _, k := range reconcilerKinds() {
		t.Run(k.name, func(t *testing.T) {
			sensors := &fakeSensors{}
			cli := fake.NewClientBuilder().WithScheme(newScheme(t)).Build()
			r := k.newReconciler(cli, sensors)

			res, err := r.Reconcile(context.Background(), k.request)
			require.NoError(t, err)
			assert.Equal(t, ctrl.Result{}, res)

			require.Len(t, sensors.deleteCalls, 1)
			assert.Equal(t, k.request.Name, sensors.deleteCalls[0].name)
			assert.Equal(t, k.expectedNamespace, sensors.deleteCalls[0].namespace)
			assert.Empty(t, sensors.addCalls, "no Add on NotFound")
		})
	}
}

func TestReconcile_Found_CallsDeleteThenAdd(t *testing.T) {
	for _, k := range reconcilerKinds() {
		t.Run(k.name, func(t *testing.T) {
			tp := k.newObject(k.request.Name)
			sensors := &fakeSensors{}
			cli := fake.NewClientBuilder().
				WithScheme(newScheme(t)).
				WithObjects(tp).
				Build()
			r := k.newReconciler(cli, sensors)

			_, err := r.Reconcile(context.Background(), k.request)
			require.NoError(t, err)

			// Delete-before-Add (best-effort cleanup of any stale state) is
			// followed by Add(tp). Same pattern as the prior informer's
			// Update path.
			require.Len(t, sensors.deleteCalls, 1)
			assert.Equal(t, k.request.Name, sensors.deleteCalls[0].name)
			assert.Equal(t, k.expectedNamespace, sensors.deleteCalls[0].namespace)

			require.Len(t, sensors.addCalls, 1)
			assert.Equal(t, k.request.Name, sensors.addCalls[0].name)
			assert.Equal(t, k.expectedNamespace, sensors.addCalls[0].namespace)
		})
	}
}

func TestReconcile_GetError_PropagatesAndDoesNothing(t *testing.T) {
	for _, k := range reconcilerKinds() {
		t.Run(k.name, func(t *testing.T) {
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
			r := k.newReconciler(cli, sensors)

			_, err := r.Reconcile(context.Background(), k.request)
			require.ErrorIs(t, err, wantErr)
			assert.Empty(t, sensors.addCalls)
			assert.Empty(t, sensors.deleteCalls)
		})
	}
}

func TestReconcile_DeleteError_DoesNotBlockAdd(t *testing.T) {
	for _, k := range reconcilerKinds() {
		t.Run(k.name, func(t *testing.T) {
			tp := k.newObject(k.request.Name)
			sensors := &fakeSensors{deleteErr: errors.New("not in collection -- fine")}
			cli := fake.NewClientBuilder().
				WithScheme(newScheme(t)).
				WithObjects(tp).
				Build()
			r := k.newReconciler(cli, sensors)

			_, err := r.Reconcile(context.Background(), k.request)
			require.NoError(t, err)
			require.Len(t, sensors.deleteCalls, 1)
			require.Len(t, sensors.addCalls, 1, "delete-before-add error must not skip the Add")
		})
	}
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

func TestRegisterReconciler_GatesOnCorrectCRD(t *testing.T) {
	for _, k := range reconcilerKinds() {
		t.Run(k.name, func(t *testing.T) {
			cm := &fakeControllerManager{}
			require.NoError(t, k.register(cm, &fakeSensors{}))
			assert.Equal(t, k.crdName, cm.gotCRD)
			assert.NotNil(t, cm.setup, "setup callback must be wired")
		})
	}
}
