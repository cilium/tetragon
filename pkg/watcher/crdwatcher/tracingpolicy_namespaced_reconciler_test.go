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
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

func newNamespacedPolicy(name, namespace string) *v1alpha1.TracingPolicyNamespaced {
	return &v1alpha1.TracingPolicyNamespaced{
		TypeMeta: metav1.TypeMeta{
			Kind:       v1alpha1.TPNamespacedKindDefinition,
			APIVersion: "cilium.io/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}
}

func TestNamespacedReconcile_NotFound_CallsDeleteWithNamespace(t *testing.T) {
	sensors := &fakeSensors{}
	cli := fake.NewClientBuilder().WithScheme(newScheme(t)).Build()
	r := &TracingPolicyNamespacedReconciler{Client: cli, Sensors: sensors}

	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "missing", Namespace: "team-a"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, res)

	require.Len(t, sensors.deleteCalls, 1)
	assert.Equal(t, "missing", sensors.deleteCalls[0].name)
	assert.Equal(t, "team-a", sensors.deleteCalls[0].namespace, "namespace must be propagated to sensors.Manager")
	assert.Empty(t, sensors.addCalls)
}

func TestNamespacedReconcile_Found_CallsDeleteThenAddWithNamespace(t *testing.T) {
	tp := newNamespacedPolicy("p1", "team-a")
	sensors := &fakeSensors{}
	cli := fake.NewClientBuilder().
		WithScheme(newScheme(t)).
		WithObjects(tp).
		Build()
	r := &TracingPolicyNamespacedReconciler{Client: cli, Sensors: sensors}

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: tp.Name, Namespace: tp.Namespace},
	})
	require.NoError(t, err)

	require.Len(t, sensors.deleteCalls, 1)
	assert.Equal(t, "p1", sensors.deleteCalls[0].name)
	assert.Equal(t, "team-a", sensors.deleteCalls[0].namespace)

	require.Len(t, sensors.addCalls, 1)
	assert.Equal(t, "p1", sensors.addCalls[0].name)
	assert.Equal(t, "team-a", sensors.addCalls[0].namespace)
}

func TestNamespacedReconcile_GetError_PropagatesAndDoesNothing(t *testing.T) {
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
	r := &TracingPolicyNamespacedReconciler{Client: cli, Sensors: sensors}

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "p1", Namespace: "team-a"},
	})
	require.ErrorIs(t, err, wantErr)
	assert.Empty(t, sensors.addCalls)
	assert.Empty(t, sensors.deleteCalls)
}

func TestNamespacedReconcile_DeleteError_DoesNotBlockAdd(t *testing.T) {
	tp := newNamespacedPolicy("p1", "team-a")
	sensors := &fakeSensors{deleteErr: errors.New("not in collection — fine")}
	cli := fake.NewClientBuilder().
		WithScheme(newScheme(t)).
		WithObjects(tp).
		Build()
	r := &TracingPolicyNamespacedReconciler{Client: cli, Sensors: sensors}

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: tp.Name, Namespace: tp.Namespace},
	})
	require.NoError(t, err)
	require.Len(t, sensors.deleteCalls, 1)
	require.Len(t, sensors.addCalls, 1, "delete-before-add error must not skip the Add")
}

func TestRegisterTracingPolicyNamespacedReconciler_GatesOnCorrectCRD(t *testing.T) {
	cm := &fakeControllerManager{}
	require.NoError(t, RegisterTracingPolicyNamespacedReconciler(cm, &fakeSensors{}))
	assert.Equal(t, v1alpha1.TPNamespacedName, cm.gotCRD)
	assert.NotNil(t, cm.setup, "setup callback must be wired")
}
