// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !nok8s

package crdwatcher

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/tetragon/pkg/reader/node"
)

// setNodeSelector sets spec.nodeSelector on either TracingPolicy kind so the
// reconciler tests can stay table-driven over reconcilerKinds().
func setNodeSelector(t *testing.T, obj client.Object, sel *slimv1.LabelSelector) {
	t.Helper()
	switch o := obj.(type) {
	case *v1alpha1.TracingPolicy:
		o.Spec.NodeSelector = sel
	case *v1alpha1.TracingPolicyNamespaced:
		o.Spec.NodeSelector = sel
	default:
		t.Fatalf("setNodeSelector: unexpected type %T", obj)
	}
}

// setLocalNodeName points node.GetNodeName() at name for the test and restores
// the package-global on cleanup so it cannot leak into other tests.
func setLocalNodeName(t *testing.T, name string) {
	t.Helper()
	t.Cleanup(node.SetNodeName) // runs after t.Setenv restores NODE_NAME
	t.Setenv("NODE_NAME", name)
	node.SetNodeName()
}

func TestNodeSelectorMatches(t *testing.T) {
	setLocalNodeName(t, "test-node")

	nodeLabels := map[string]string{
		"node-role":          "gpu",
		"kubernetes.io/arch": "amd64",
	}
	cli := fake.NewClientBuilder().
		WithScheme(newScheme(t)).
		WithObjects(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "test-node", Labels: nodeLabels}}).
		Build()

	tests := []struct {
		name     string
		selector *slimv1.LabelSelector
		want     bool
	}{
		{"nil selects all", nil, true},
		{"empty selects all", &slimv1.LabelSelector{}, true},
		{"matchLabels hit", &slimv1.LabelSelector{MatchLabels: map[string]string{"node-role": "gpu"}}, true},
		{"matchLabels miss", &slimv1.LabelSelector{MatchLabels: map[string]string{"node-role": "cpu"}}, false},
		{"In hit", &slimv1.LabelSelector{MatchExpressions: []slimv1.LabelSelectorRequirement{
			{Key: "kubernetes.io/arch", Operator: slimv1.LabelSelectorOpIn, Values: []string{"amd64", "arm64"}}}}, true},
		{"NotIn miss", &slimv1.LabelSelector{MatchExpressions: []slimv1.LabelSelectorRequirement{
			{Key: "kubernetes.io/arch", Operator: slimv1.LabelSelectorOpNotIn, Values: []string{"amd64"}}}}, false},
		{"Exists hit", &slimv1.LabelSelector{MatchExpressions: []slimv1.LabelSelectorRequirement{
			{Key: "node-role", Operator: slimv1.LabelSelectorOpExists}}}, true},
		{"DoesNotExist hit", &slimv1.LabelSelector{MatchExpressions: []slimv1.LabelSelectorRequirement{
			{Key: "absent", Operator: slimv1.LabelSelectorOpDoesNotExist}}}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := nodeSelectorMatches(context.Background(), cli, tt.selector)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestNodeSelectorMatches_NodeReadError(t *testing.T) {
	setLocalNodeName(t, "missing-node")
	cli := fake.NewClientBuilder().WithScheme(newScheme(t)).Build()
	_, err := nodeSelectorMatches(context.Background(), cli,
		&slimv1.LabelSelector{MatchLabels: map[string]string{"a": "b"}})
	require.Error(t, err, "missing node must surface as an error (caller fails open)")
}

func TestReconcile_NodeSelector(t *testing.T) {
	setLocalNodeName(t, "test-node")
	localNode := &corev1.Node{ObjectMeta: metav1.ObjectMeta{
		Name:   "test-node",
		Labels: map[string]string{"node-role": "gpu"},
	}}

	for _, k := range reconcilerKinds() {
		t.Run(k.name+"/match_adds", func(t *testing.T) {
			tp := k.newObject(k.request.Name)
			setNodeSelector(t, tp, &slimv1.LabelSelector{MatchLabels: map[string]string{"node-role": "gpu"}})
			sensors := &fakeSensors{}
			cli := fake.NewClientBuilder().WithScheme(newScheme(t)).WithObjects(tp, localNode).Build()
			r := k.newReconciler(cli, sensors)

			_, err := r.Reconcile(context.Background(), k.request)
			require.NoError(t, err)
			require.Len(t, sensors.addCalls, 1, "matching node should load the policy")
		})

		t.Run(k.name+"/nomatch_skips_add", func(t *testing.T) {
			tp := k.newObject(k.request.Name)
			setNodeSelector(t, tp, &slimv1.LabelSelector{MatchLabels: map[string]string{"node-role": "cpu"}})
			sensors := &fakeSensors{}
			cli := fake.NewClientBuilder().WithScheme(newScheme(t)).WithObjects(tp, localNode).Build()
			r := k.newReconciler(cli, sensors)

			_, err := r.Reconcile(context.Background(), k.request)
			require.NoError(t, err)
			require.Empty(t, sensors.addCalls, "non-matching node must not load the policy")
			require.Len(t, sensors.skippedCalls, 1, "non-matching policy is tracked as skipped")
			require.Len(t, sensors.deleteCalls, 1, "delete-before-add still unloads any prior instance")
		})

		t.Run(k.name+"/nomatch_skip_error_requeues", func(t *testing.T) {
			tp := k.newObject(k.request.Name)
			setNodeSelector(t, tp, &slimv1.LabelSelector{MatchLabels: map[string]string{"node-role": "cpu"}})
			wantErr := errors.New("boom")
			sensors := &fakeSensors{skippedErr: wantErr}
			cli := fake.NewClientBuilder().WithScheme(newScheme(t)).WithObjects(tp, localNode).Build()
			r := k.newReconciler(cli, sensors)

			// A non-terminal error is returned so the policy is retried rather
			// than left untracked.
			_, err := r.Reconcile(context.Background(), k.request)
			require.ErrorIs(t, err, wantErr)
			require.NotErrorIs(t, err, reconcile.TerminalError(nil))
		})

		t.Run(k.name+"/failopen_on_node_read_error", func(t *testing.T) {
			tp := k.newObject(k.request.Name)
			setNodeSelector(t, tp, &slimv1.LabelSelector{MatchLabels: map[string]string{"node-role": "gpu"}})
			sensors := &fakeSensors{}
			// Local node is absent from the client: evaluation errors and the
			// gate must fail open and still load the policy.
			cli := fake.NewClientBuilder().WithScheme(newScheme(t)).WithObjects(tp).Build()
			r := k.newReconciler(cli, sensors)

			_, err := r.Reconcile(context.Background(), k.request)
			require.NoError(t, err)
			require.Len(t, sensors.addCalls, 1, "node read error must load the policy (fail open)")
		})
	}
}

func TestMapNodeToPolicies(t *testing.T) {
	for _, k := range reconcilerKinds() {
		t.Run(k.name, func(t *testing.T) {
			withSel := k.newObject("p1")
			setNodeSelector(t, withSel, &slimv1.LabelSelector{MatchLabels: map[string]string{"a": "b"}})
			withoutSel := k.newObject("p2") // no nodeSelector -> must be skipped
			cli := fake.NewClientBuilder().WithScheme(newScheme(t)).WithObjects(withSel, withoutSel).Build()
			r := k.newReconciler(cli, &fakeSensors{})

			var reqs []reconcile.Request
			switch rr := r.(type) {
			case *TracingPolicyReconciler:
				reqs = rr.mapNodeToPolicies(context.Background(), &corev1.Node{})
			case *TracingPolicyNamespacedReconciler:
				reqs = rr.mapNodeToPolicies(context.Background(), &corev1.Node{})
			}
			require.Len(t, reqs, 1, "only policies with a nodeSelector should be re-enqueued")
			require.Equal(t, "p1", reqs[0].Name)
		})
	}
}

// TestIsLocalNode covers the Node watch predicate: only the agent's own node
// passes, so a relabel of any other node is filtered out before the mapper.
func TestIsLocalNode(t *testing.T) {
	setLocalNodeName(t, "test-node")
	require.True(t, isLocalNode(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "test-node"}}))
	require.False(t, isLocalNode(&corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "other-node"}}),
		"the Node watch predicate must ignore other nodes")
}
