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

// AddSkippedTracingPolicy satisfies sensorManager. No policy here sets a
// nodeSelector, so it is never called; nodeselector_test.go covers that path.
func (r *recordingSensors) AddSkippedTracingPolicy(_ context.Context, _ tracingpolicy.TracingPolicy) error {
	return nil
}

func (r *recordingSensors) DeleteTracingPolicy(_ context.Context, name, _, _ string) error {
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

type integrationKind struct {
	name            string
	namePrefix      string
	namespace       string
	setupReconciler func(ctrl.Manager, sensorManager) error
	createObject    func(name string) client.Object
	blankObject     func() client.Object
}

func integrationKinds() []integrationKind {
	return []integrationKind{
		{
			name:       "cluster_scoped",
			namePrefix: "test-tp",
			namespace:  "",
			setupReconciler: func(mgr ctrl.Manager, s sensorManager) error {
				return (&TracingPolicyReconciler{Client: mgr.GetClient(), Sensors: s}).SetupWithManager(mgr)
			},
			createObject: func(name string) client.Object {
				return &v1alpha1.TracingPolicy{
					ObjectMeta: metav1.ObjectMeta{Name: name},
					Spec:       v1alpha1.TracingPolicySpec{},
				}
			},
			blankObject: func() client.Object { return &v1alpha1.TracingPolicy{} },
		},
		{
			name:       "namespaced",
			namePrefix: "test-tpn",
			namespace:  "default",
			setupReconciler: func(mgr ctrl.Manager, s sensorManager) error {
				return (&TracingPolicyNamespacedReconciler{Client: mgr.GetClient(), Sensors: s}).SetupWithManager(mgr)
			},
			createObject: func(name string) client.Object {
				return &v1alpha1.TracingPolicyNamespaced{
					ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
					Spec:       v1alpha1.TracingPolicySpec{},
				}
			},
			blankObject: func() client.Object { return &v1alpha1.TracingPolicyNamespaced{} },
		},
	}
}

// flipSpec toggles a spec field so the next Update bumps generation. Both
// policy types embed the same TracingPolicySpec, so a single type switch
// covers both kinds.
func flipSpec(obj client.Object) {
	switch tp := obj.(type) {
	case *v1alpha1.TracingPolicy:
		tp.Spec.Loader = !tp.Spec.Loader
	case *v1alpha1.TracingPolicyNamespaced:
		tp.Spec.Loader = !tp.Spec.Loader
	}
}

// setTestAnnotation adds an annotation that does NOT bump generation, so the
// GenerationChangedPredicate is expected to filter the resulting watch event.
// Works for both kinds via the metav1.Object interface embedded in
// client.Object.
func setTestAnnotation(obj client.Object) {
	annotations := obj.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations["tetragon.io/test"] = "annotated"
	obj.SetAnnotations(annotations)
}

// retryUpdate fetches the latest version of the policy, applies the mutation,
// and Updates. It retries on conflict so the test does not flake on parallel
// reconcile-driven status writes. Works for both kinds because newObj/mutate
// operate on the client.Object interface.
func retryUpdate(ctx context.Context, cli client.Client, key types.NamespacedName, newObj func() client.Object, mutate func(client.Object)) error {
	deadline := time.Now().Add(10 * time.Second)
	for {
		obj := newObj()
		if err := cli.Get(ctx, key, obj); err != nil {
			return err
		}
		mutate(obj)
		err := cli.Update(ctx, obj)
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

// TestReconciler_PredicateBehavior runs both Reconciler implementations
// (cluster-scoped and namespaced) against a real apiserver to verify that the
// GenerationChangedPredicate routes pod-policy lifecycle events into the
// expected sensors calls. A recordingSensors fake captures Add/Delete so the
// test asserts on side effects rather than BPF state. Each kind walks the same
// four steps:
//
//  1. Create: reconcile fires and AddTracingPolicy is called.
//  2. Annotation-only patch (no generation bump): the predicate filters it, so
//     no Add/Delete happens.
//  3. Spec mutation (generation bump): DeleteTracingPolicy then AddTracingPolicy.
//  4. Delete: reconcile sees NotFound and calls DeleteTracingPolicy.
//
// Requires a Kind cluster with the TracingPolicy and TracingPolicyNamespaced
// CRDs installed (same scaffolding pkg/manager/manager_integration_test.go
// relies on).
func TestReconciler_PredicateBehavior(t *testing.T) {
	for _, k := range integrationKinds() {
		t.Run(k.name, func(t *testing.T) {
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
			require.NoError(t, k.setupReconciler(mgr, sensors))

			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			go func() {
				_ = mgr.Start(ctx)
			}()
			require.True(t, mgr.GetCache().WaitForCacheSync(ctx))

			cli, err := client.New(cfg, client.Options{Scheme: scheme})
			require.NoError(t, err)

			tpName := fmt.Sprintf("%s-%d", k.namePrefix, time.Now().UnixNano())
			key := types.NamespacedName{Name: tpName, Namespace: k.namespace}
			t.Cleanup(func() {
				_ = cli.Delete(context.Background(), k.createObject(tpName))
			})

			// (1) Create -> Reconciler fires -> Add.
			require.NoError(t, cli.Create(ctx, k.createObject(tpName)))
			require.Eventually(t, func() bool {
				adds, _ := sensors.snapshot()
				return len(adds) >= 1 && adds[len(adds)-1] == tpName
			}, 30*time.Second, 200*time.Millisecond, "Add should be called on create")

			addsAfterCreate, deletesAfterCreate := sensors.snapshot()

			// (2) Annotation-only patch -> no spec change, no generation bump
			// -> GenerationChangedPredicate filters this out -> no extra
			// Add/Delete.
			require.NoError(t, retryUpdate(ctx, cli, key, k.blankObject, setTestAnnotation))

			// Wait long enough that, if reconcile *were* going to fire
			// spuriously, it would have done so. Then assert no new calls.
			time.Sleep(2 * time.Second)
			addsAfterAnnotate, deletesAfterAnnotate := sensors.snapshot()
			assert.Equal(t, addsAfterCreate, addsAfterAnnotate, "annotation patch must not trigger Add")
			assert.Equal(t, deletesAfterCreate, deletesAfterAnnotate, "annotation patch must not trigger Delete")

			// (3) Mutate spec -> Reconciler fires -> Delete + Add.
			require.NoError(t, retryUpdate(ctx, cli, key, k.blankObject, flipSpec))
			require.Eventually(t, func() bool {
				adds, deletes := sensors.snapshot()
				return len(adds) > len(addsAfterAnnotate) && len(deletes) > len(deletesAfterAnnotate)
			}, 30*time.Second, 200*time.Millisecond, "spec mutation should trigger Delete+Add")

			addsAfterSpec, deletesAfterSpec := sensors.snapshot()

			// (4) Delete -> Reconciler fires with NotFound -> Delete.
			require.NoError(t, cli.Delete(ctx, k.createObject(tpName)))
			require.Eventually(t, func() bool {
				_, deletes := sensors.snapshot()
				return len(deletes) > len(deletesAfterSpec)
			}, 30*time.Second, 200*time.Millisecond, "delete should trigger Delete on sensors")

			finalAdds, _ := sensors.snapshot()
			assert.Len(t, finalAdds, len(addsAfterSpec), "Delete must not trigger Add")
		})
	}
}
