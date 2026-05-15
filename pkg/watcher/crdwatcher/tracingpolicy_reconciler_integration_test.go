// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build integration && !nok8s

package crdwatcher

import (
	"context"
	"fmt"
	"sync"
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
	"github.com/cilium/tetragon/pkg/tracingpolicy"
)

// recordingSensors is a thread-safe fake sensors.Manager that records all
// Add/Delete calls. The envtest harness drives Reconcile concurrently via
// controller-runtime, so the recorder must be safe for concurrent use.
type recordingSensors struct {
	mu      sync.Mutex
	adds    []string
	deletes []string
}

func (r *recordingSensors) AddTracingPolicy(_ context.Context, tp tracingpolicy.TracingPolicy) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.adds = append(r.adds, tp.TpName())
	return nil
}

func (r *recordingSensors) DeleteTracingPolicy(_ context.Context, name, _ string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deletes = append(r.deletes, name)
	return nil
}

func (r *recordingSensors) snapshot() (adds, deletes []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.adds...), append([]string(nil), r.deletes...)
}

// TestTracingPolicyReconciler_PredicateBehavior asserts the four key behaviors
// documented in the issue: create→Add; status patch→silent; spec mutate→
// Delete+Add; delete→Delete.
//
// Requires a Kind cluster with the TracingPolicy CRD installed (the same
// scaffolding pkg/manager/manager_integration_test.go relies on).
func TestTracingPolicyReconciler_PredicateBehavior(t *testing.T) {
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
	r := &TracingPolicyReconciler{Client: mgr.GetClient(), Sensors: sensors}
	require.NoError(t, r.SetupWithManager(mgr))

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		_ = mgr.Start(ctx)
	}()
	require.True(t, mgr.GetCache().WaitForCacheSync(ctx))

	cli, err := client.New(cfg, client.Options{Scheme: scheme})
	require.NoError(t, err)

	tpName := fmt.Sprintf("test-tp-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_ = cli.Delete(context.Background(), &v1alpha1.TracingPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: tpName},
		})
	})

	// (1) Create → Reconciler fires → Add.
	tp := &v1alpha1.TracingPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: tpName},
		Spec:       v1alpha1.TracingPolicySpec{},
	}
	require.NoError(t, cli.Create(ctx, tp))

	require.Eventually(t, func() bool {
		adds, _ := sensors.snapshot()
		return len(adds) >= 1 && adds[len(adds)-1] == tpName
	}, 30*time.Second, 200*time.Millisecond, "Add should be called on create")

	addsAfterCreate, deletesAfterCreate := sensors.snapshot()

	// (2) Patch annotations only (no spec change, no generation bump) →
	// GenerationChangedPredicate filters this out → no extra Add/Delete.
	require.NoError(t, retryUpdate(ctx, cli, tpName, func(obj *v1alpha1.TracingPolicy) {
		if obj.Annotations == nil {
			obj.Annotations = map[string]string{}
		}
		obj.Annotations["tetragon.io/test"] = "annotated"
	}))

	// Wait long enough that, if reconcile *were* going to fire spuriously,
	// it would have done so. Then assert no new calls.
	time.Sleep(2 * time.Second)
	addsAfterAnnotate, deletesAfterAnnotate := sensors.snapshot()
	assert.Equal(t, addsAfterCreate, addsAfterAnnotate, "annotation patch must not trigger Add")
	assert.Equal(t, deletesAfterCreate, deletesAfterAnnotate, "annotation patch must not trigger Delete")

	// (3) Mutate spec → Reconciler fires → Delete + Add.
	require.NoError(t, retryUpdate(ctx, cli, tpName, func(obj *v1alpha1.TracingPolicy) {
		obj.Spec.Loader = !obj.Spec.Loader
	}))

	require.Eventually(t, func() bool {
		adds, deletes := sensors.snapshot()
		return len(adds) > len(addsAfterAnnotate) && len(deletes) > len(deletesAfterAnnotate)
	}, 30*time.Second, 200*time.Millisecond, "spec mutation should trigger Delete+Add")

	addsAfterSpec, deletesAfterSpec := sensors.snapshot()

	// (4) Delete → Reconciler fires with NotFound → Delete.
	require.NoError(t, cli.Delete(ctx, &v1alpha1.TracingPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: tpName},
	}))

	require.Eventually(t, func() bool {
		_, deletes := sensors.snapshot()
		return len(deletes) > len(deletesAfterSpec)
	}, 30*time.Second, 200*time.Millisecond, "delete should trigger Delete on sensors")

	finalAdds, _ := sensors.snapshot()
	assert.Equal(t, len(addsAfterSpec), len(finalAdds), "Delete must not trigger Add")
}

// retryUpdate fetches the latest version of the policy, applies the mutation,
// and Updates. It retries on conflict so the test does not flake on parallel
// reconcile-driven status writes.
func retryUpdate(ctx context.Context, cli client.Client, name string, mutate func(*v1alpha1.TracingPolicy)) error {
	deadline := time.Now().Add(10 * time.Second)
	for {
		tp := &v1alpha1.TracingPolicy{}
		if err := cli.Get(ctx, types.NamespacedName{Name: name}, tp); err != nil {
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
