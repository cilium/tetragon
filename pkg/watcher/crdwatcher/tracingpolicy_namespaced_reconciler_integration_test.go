// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build integration && !nok8s

package crdwatcher

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
)

// TestTracingPolicyNamespacedReconciler_PredicateBehavior asserts the same
// four key behaviors as the cluster-scoped smoke test, with namespace
// propagation: create→Add(namespace); status patch→silent; spec mutate→
// Delete+Add; delete→Delete(namespace).
//
// Requires a Kind cluster with the TracingPolicyNamespaced CRD installed.
func TestTracingPolicyNamespacedReconciler_PredicateBehavior(t *testing.T) {
	useExistingCluster := true
	testEnv := &envtest.Environment{UseExistingCluster: &useExistingCluster}
	cfg, err := testEnv.Start()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, testEnv.Stop()) })

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(v1alpha1.AddToScheme(scheme))

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:  scheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
	})
	require.NoError(t, err)

	sensors := &recordingSensors{}
	r := &TracingPolicyNamespacedReconciler{Client: mgr.GetClient(), Sensors: sensors}
	require.NoError(t, r.SetupWithManager(mgr))

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		_ = mgr.Start(ctx)
	}()
	require.True(t, mgr.GetCache().WaitForCacheSync(ctx))

	cli, err := client.New(cfg, client.Options{Scheme: scheme})
	require.NoError(t, err)

	const namespace = "default"
	tpName := fmt.Sprintf("test-tpn-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_ = cli.Delete(context.Background(), &v1alpha1.TracingPolicyNamespaced{
			ObjectMeta: metav1.ObjectMeta{Name: tpName, Namespace: namespace},
		})
	})

	// (1) Create → Reconciler fires → Add.
	tp := &v1alpha1.TracingPolicyNamespaced{
		ObjectMeta: metav1.ObjectMeta{Name: tpName, Namespace: namespace},
		Spec:       v1alpha1.TracingPolicySpec{},
	}
	require.NoError(t, cli.Create(ctx, tp))

	require.Eventually(t, func() bool {
		adds, _ := sensors.snapshot()
		return len(adds) >= 1 && adds[len(adds)-1] == tpName
	}, 30*time.Second, 200*time.Millisecond, "Add should be called on create")

	addsAfterCreate, deletesAfterCreate := sensors.snapshot()

	// (2) Annotation-only patch → no spec change, no generation bump → no
	// reconcile (GenerationChangedPredicate filter).
	require.NoError(t, retryUpdateNamespaced(ctx, cli, namespace, tpName, func(obj *v1alpha1.TracingPolicyNamespaced) {
		if obj.Annotations == nil {
			obj.Annotations = map[string]string{}
		}
		obj.Annotations["tetragon.io/test"] = "annotated"
	}))

	time.Sleep(2 * time.Second)
	addsAfterAnnotate, deletesAfterAnnotate := sensors.snapshot()
	assert.Equal(t, addsAfterCreate, addsAfterAnnotate, "annotation patch must not trigger Add")
	assert.Equal(t, deletesAfterCreate, deletesAfterAnnotate, "annotation patch must not trigger Delete")

	// (3) Mutate spec → Reconciler fires → Delete + Add.
	require.NoError(t, retryUpdateNamespaced(ctx, cli, namespace, tpName, func(obj *v1alpha1.TracingPolicyNamespaced) {
		obj.Spec.Loader = !obj.Spec.Loader
	}))

	require.Eventually(t, func() bool {
		adds, deletes := sensors.snapshot()
		return len(adds) > len(addsAfterAnnotate) && len(deletes) > len(deletesAfterAnnotate)
	}, 30*time.Second, 200*time.Millisecond, "spec mutation should trigger Delete+Add")

	addsAfterSpec, deletesAfterSpec := sensors.snapshot()

	// (4) Delete → Reconciler fires with NotFound → Delete.
	require.NoError(t, cli.Delete(ctx, &v1alpha1.TracingPolicyNamespaced{
		ObjectMeta: metav1.ObjectMeta{Name: tpName, Namespace: namespace},
	}))

	require.Eventually(t, func() bool {
		_, deletes := sensors.snapshot()
		return len(deletes) > len(deletesAfterSpec)
	}, 30*time.Second, 200*time.Millisecond, "delete should trigger Delete on sensors")

	finalAdds, _ := sensors.snapshot()
	assert.Equal(t, len(addsAfterSpec), len(finalAdds), "Delete must not trigger Add")
}

// retryUpdateNamespaced is the namespaced counterpart of retryUpdate.
func retryUpdateNamespaced(ctx context.Context, cli client.Client, namespace, name string, mutate func(*v1alpha1.TracingPolicyNamespaced)) error {
	deadline := time.Now().Add(10 * time.Second)
	for {
		tp := &v1alpha1.TracingPolicyNamespaced{}
		if err := cli.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, tp); err != nil {
			return err
		}
		mutate(tp)
		err := cli.Update(ctx, tp)
		if err == nil {
			return nil
		}
		if !apierrors.IsConflict(err) {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("update conflict after deadline: %w", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
