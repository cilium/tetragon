// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package nodeselector_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"
	"sigs.k8s.io/e2e-framework/klient/k8s/resources"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/features"
	k8syaml "sigs.k8s.io/yaml"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	slimv1 "github.com/cilium/tetragon/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/tetragon/tests/e2e/flags"
	"github.com/cilium/tetragon/tests/e2e/helpers"
	"github.com/cilium/tetragon/tests/e2e/runners"
	"github.com/cilium/tetragon/tests/e2e/state"
)

// This suite exercises spec.nodeSelector end-to-end on a multi-node cluster:
// a policy must be loaded only on agents whose node labels match the selector.
// Verification is per-agent via the ListTracingPolicies gRPC (the feature gates
// loading, not events), reusing the per-pod connections the runner sets up. A
// non-matching node must not have the policy at all (absent), not merely
// disabled — a present-but-errored policy would indicate a gate failure.
//
// The label used to group nodes is an arbitrary test label ("nodegroup"): the
// two workers are labelled a and b, the control-plane is left unlabelled.

// nodegroupLabel is an arbitrary, test-only node label used to partition the
// workers. It intentionally carries no real meaning (no hardware/role implied).
const nodegroupLabel = "nodegroup"

// rpcTimeout bounds each ListTracingPolicies call so one hung RPC cannot defeat
// the retry budget of waitPolicyOnNode.
const rpcTimeout = 5 * time.Second

var runner *runners.Runner

// Discovered during setup. The control-plane carries no nodegroup label; the
// two workers are labelled nodegroup=a and nodegroup=b respectively.
var (
	nodeA      string // worker with nodegroup=a
	nodeB      string // worker with nodegroup=b
	ctrlNode   string // control-plane (no nodegroup label)
	skipReason string
)

// 1 control-plane + 2 workers, each with the mounts the agent needs. The two
// workers carry the arbitrary test labels nodegroup=a and nodegroup=b; the
// control-plane is intentionally left unlabelled.
//
// Each node mounts a DISTINCT host bpffs subdirectory at /sys/fs/bpf. The agent
// (via the chart's hostPath bpf-maps volume) pins programs under the node's
// /sys/fs/bpf, so all nodes sharing one host bpffs would make the agents clobber
// each other's pins (e.g. /sys/fs/bpf/tetragon/__base__/...), crashing the base
// sensor. Per-node subdirectories give each agent an isolated pin namespace.
const multiNodeKindConfig = `
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
  - hostPath: "/proc"
    containerPath: "/procRoot"
  - hostPath: "/tetragonExport"
    containerPath: "/tetragonExport"
  - hostPath: "/sys/fs/bpf/tetragon-e2e-cp"
    containerPath: "/sys/fs/bpf"
    propagation: Bidirectional
- role: worker
  labels:
    nodegroup: a
  extraMounts:
  - hostPath: "/proc"
    containerPath: "/procRoot"
  - hostPath: "/tetragonExport"
    containerPath: "/tetragonExport"
  - hostPath: "/sys/fs/bpf/tetragon-e2e-a"
    containerPath: "/sys/fs/bpf"
    propagation: Bidirectional
- role: worker
  labels:
    nodegroup: b
  extraMounts:
  - hostPath: "/proc"
    containerPath: "/procRoot"
  - hostPath: "/tetragonExport"
    containerPath: "/tetragonExport"
  - hostPath: "/sys/fs/bpf/tetragon-e2e-b"
    containerPath: "/sys/fs/bpf"
    propagation: Bidirectional
`

func TestMain(m *testing.M) {
	runner = runners.NewRunner().
		WithSetupClusterFn(func(testenv env.Environment) env.Func {
			return helpers.MaybeCreateTempKindClusterWithConfig(testenv, runners.ClusterPrefix, multiNodeKindConfig)
		}).
		Init()

	// Discover the worker nodes labelled by the kind config. If fewer than two
	// workers exist (e.g. a pre-existing single-node cluster), record a skip
	// reason instead of failing — the per-node assertions need >=2 nodes.
	runner.Setup(func(ctx context.Context, c *envconf.Config) (context.Context, error) {
		return discoverNodes(ctx, c)
	})

	runner.Run(m)
}

func discoverNodes(ctx context.Context, c *envconf.Config) (context.Context, error) {
	client, err := c.NewClient()
	if err != nil {
		return ctx, fmt.Errorf("discoverNodes: new client: %w", err)
	}
	nodes := &corev1.NodeList{}
	if err := client.Resources().List(ctx, nodes); err != nil {
		return ctx, fmt.Errorf("discoverNodes: list nodes: %w", err)
	}
	var workers []corev1.Node
	for i := range nodes.Items {
		n := nodes.Items[i]
		if _, isCP := n.Labels["node-role.kubernetes.io/control-plane"]; isCP {
			ctrlNode = n.Name
			continue
		}
		workers = append(workers, n)
	}
	if len(workers) < 2 || ctrlNode == "" {
		skipReason = fmt.Sprintf("nodeSelector e2e needs a control-plane and >=2 worker nodes; found ctrl=%q workers=%d", ctrlNode, len(workers))
		klog.Warning(skipReason)
		return ctx, nil
	}

	// Prefer the nodegroup labels set by the kind config.
	for _, w := range workers {
		switch w.Labels[nodegroupLabel] {
		case "a":
			nodeA = w.Name
		case "b":
			nodeB = w.Name
		}
	}
	switch {
	case nodeA != "" && nodeB != "":
		// Both labels present (the normal kind-config path).
	case nodeA == "" && nodeB == "":
		// No labels (attached to a pre-existing cluster): label two workers.
		nodeA, nodeB = workers[0].Name, workers[1].Name
		if err := labelNode(ctx, c, nodeA, nodegroupLabel, "a"); err != nil {
			return ctx, err
		}
		if err := labelNode(ctx, c, nodeB, nodegroupLabel, "b"); err != nil {
			return ctx, err
		}
	default:
		// Exactly one labelled worker: ambiguous, skip rather than mislabel.
		skipReason = "nodeSelector e2e: found only one nodegroup-labelled worker; need both a and b"
		klog.Warning(skipReason)
		return ctx, nil
	}
	klog.Infof("nodeSelector e2e nodes: nodegroup=a:%s nodegroup=b:%s control-plane:%s", nodeA, nodeB, ctrlNode)
	return ctx, nil
}

// labelNode sets (val != "") or removes (val == "") a label on a node. The
// read-modify-write is retried on conflict, since the kubelet updates node
// objects (status, leases) frequently.
func labelNode(ctx context.Context, c *envconf.Config, node, key, val string) error {
	client, err := c.NewClient()
	if err != nil {
		return fmt.Errorf("labelNode: new client: %w", err)
	}
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var n corev1.Node
		if err := client.Resources().Get(ctx, node, "", &n); err != nil {
			return err
		}
		if n.Labels == nil {
			n.Labels = map[string]string{}
		}
		if val == "" {
			delete(n.Labels, key)
		} else {
			n.Labels[key] = val
		}
		return client.Resources().Update(ctx, &n)
	})
}

// tetragonConnForNode returns the forwarded gRPC connection to the Tetragon
// agent running on nodeName.
func tetragonConnForNode(ctx context.Context, c *envconf.Config, nodeName string) (*grpc.ClientConn, error) {
	opts, ok := ctx.Value(state.InstallOpts).(*flags.HelmOptions)
	if !ok {
		return nil, errors.New("missing Tetragon install options in context")
	}
	client, err := c.NewClient()
	if err != nil {
		return nil, fmt.Errorf("new client: %w", err)
	}
	pods := &corev1.PodList{}
	if err := client.Resources(opts.Namespace).List(ctx, pods,
		resources.WithLabelSelector("app.kubernetes.io/name="+opts.DaemonSetName)); err != nil {
		return nil, fmt.Errorf("list tetragon pods: %w", err)
	}
	var podName string
	for i := range pods.Items {
		if pods.Items[i].Spec.NodeName == nodeName {
			podName = pods.Items[i].Name
			break
		}
	}
	if podName == "" {
		return nil, fmt.Errorf("no Tetragon pod found on node %s", nodeName)
	}
	conns, ok := ctx.Value(state.GrpcForwardedConns).(map[string]*grpc.ClientConn)
	if !ok {
		return nil, errors.New("missing forwarded gRPC connections in context")
	}
	conn := conns[podName]
	if conn == nil {
		return nil, fmt.Errorf("no gRPC connection for pod %s (node %s)", podName, nodeName)
	}
	return conn, nil
}

// policyStatus reports whether policyName is present in the agent reachable
// through conn and, if so, whether it is enabled (loaded with no error). A
// gated-out node should have it absent (present == false), not merely disabled.
func policyStatus(ctx context.Context, conn *grpc.ClientConn, policyName string) (present, enabled bool, err error) {
	rpcCtx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()
	res, err := tetragon.NewFineGuidanceSensorsClient(conn).
		ListTracingPolicies(rpcCtx, &tetragon.ListTracingPoliciesRequest{})
	if err != nil {
		return false, false, err
	}
	for _, pol := range res.GetPolicies() {
		if pol.GetName() == policyName {
			return true, pol.State == tetragon.TracingPolicyState_TP_STATE_ENABLED && pol.Error == "", nil
		}
	}
	return false, false, nil
}

// waitPolicyOnNode resolves the agent on nodeName once, then polls until
// policyName reaches the wanted state, or fails after maxTries. want==true
// means the policy must be present and enabled; want==false means it must be
// absent (not just disabled).
func waitPolicyOnNode(ctx context.Context, c *envconf.Config, policyName, nodeName string, want bool, maxTries int) error {
	conn, err := tetragonConnForNode(ctx, c, nodeName)
	if err != nil {
		return err
	}
	var present, enabled bool
	var lastErr error
	for range maxTries {
		present, enabled, lastErr = policyStatus(ctx, conn, policyName)
		if lastErr == nil && ((want && present && enabled) || (!want && !present)) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	msg := fmt.Sprintf("policy %q on node %s did not reach loaded=%v (present=%v enabled=%v)",
		policyName, nodeName, want, present, enabled)
	if lastErr != nil {
		return fmt.Errorf("%s: %w", msg, lastErr)
	}
	return errors.New(msg)
}

func allNodes() []string { return []string{nodeA, nodeB, ctrlNode} }

// nodeSelectorPolicy renders a minimal TracingPolicy carrying the given
// nodeSelector. The policy is built from the typed API and marshalled, so
// callers express selectors as Go values and never hand-write YAML.
func nodeSelectorPolicy(t *testing.T, name string, sel *slimv1.LabelSelector) string {
	t.Helper()
	tp := v1alpha1.TracingPolicy{
		TypeMeta:   metav1.TypeMeta{APIVersion: "cilium.io/v1alpha1", Kind: "TracingPolicy"},
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v1alpha1.TracingPolicySpec{
			NodeSelector: sel,
			KProbes:      []v1alpha1.KProbeSpec{{Call: "tcp_connect"}},
		},
	}
	out, err := k8syaml.Marshal(&tp)
	require.NoError(t, err, "marshal TracingPolicy")
	return string(out)
}

// runCase installs a policy, asserts it loads on every node in matchNodes and
// is absent on all others, then uninstalls it.
func runCase(t *testing.T, name string, sel *slimv1.LabelSelector, matchNodes []string) {
	if skipReason != "" {
		t.Skip(skipReason)
	}
	policyYAML := nodeSelectorPolicy(t, name, sel)
	others := slices.DeleteFunc(allNodes(), func(n string) bool {
		return slices.Contains(matchNodes, n)
	})

	// Best-effort uninstall even if an assessment fails (the suite runs with
	// -fail-fast, which skips feature Teardown steps).
	var cfg *envconf.Config
	t.Cleanup(func() {
		if cfg != nil {
			_, _ = helpers.UnloadCRDString("", policyYAML, false)(context.Background(), cfg)
		}
	})

	feat := features.New(name).
		Assess("install policy", func(ctx context.Context, t *testing.T, c *envconf.Config) context.Context {
			cfg = c
			ctx, err := helpers.LoadCRDString("", policyYAML, false)(ctx, c)
			require.NoError(t, err, "install policy")
			return ctx
		}).
		Assess("loaded on matching nodes", func(ctx context.Context, t *testing.T, c *envconf.Config) context.Context {
			for _, n := range matchNodes {
				require.NoError(t, waitPolicyOnNode(ctx, c, name, n, true, 30),
					"policy %s must load on matching node %s", name, n)
			}
			return ctx
		}).
		Assess("absent on non-matching nodes", func(ctx context.Context, t *testing.T, c *envconf.Config) context.Context {
			// Matching nodes are confirmed loaded; give all agents a moment to
			// settle, then assert the gated agents never even receive it.
			time.Sleep(3 * time.Second)
			for _, n := range others {
				conn, err := tetragonConnForNode(ctx, c, n)
				require.NoError(t, err)
				for range 3 {
					present, _, err := policyStatus(ctx, conn, name)
					require.NoError(t, err)
					require.False(t, present, "policy %s must be absent on non-matching node %s", name, n)
					time.Sleep(time.Second)
				}
			}
			return ctx
		}).
		Assess("uninstall policy", func(ctx context.Context, t *testing.T, c *envconf.Config) context.Context {
			ctx, err := helpers.UnloadCRDString("", policyYAML, false)(ctx, c)
			require.NoError(t, err, "uninstall policy")
			return ctx
		}).
		Feature()

	runner.Test(t, feat)
}

func TestNodeSelectorMatchLabels(t *testing.T) {
	runCase(t, "node-selector-matchlabels-a",
		&slimv1.LabelSelector{MatchLabels: map[string]string{nodegroupLabel: "a"}},
		[]string{nodeA})
}

func TestNodeSelectorMatchExpressionsIn(t *testing.T) {
	runCase(t, "node-selector-in-a-b",
		&slimv1.LabelSelector{MatchExpressions: []slimv1.LabelSelectorRequirement{
			{Key: nodegroupLabel, Operator: slimv1.LabelSelectorOpIn, Values: []string{"a", "b"}},
		}},
		[]string{nodeA, nodeB})
}

func TestNodeSelectorExists(t *testing.T) {
	runCase(t, "node-selector-exists-nodegroup",
		&slimv1.LabelSelector{MatchExpressions: []slimv1.LabelSelectorRequirement{
			{Key: nodegroupLabel, Operator: slimv1.LabelSelectorOpExists},
		}},
		[]string{nodeA, nodeB})
}

func TestNodeSelectorDoesNotExist(t *testing.T) {
	runCase(t, "node-selector-doesnotexist-nodegroup",
		&slimv1.LabelSelector{MatchExpressions: []slimv1.LabelSelectorRequirement{
			{Key: nodegroupLabel, Operator: slimv1.LabelSelectorOpDoesNotExist},
		}},
		[]string{ctrlNode})
}

func TestNodeSelectorNoMatch(t *testing.T) {
	// Negative: a selector that matches no node must load nowhere.
	runCase(t, "node-selector-nomatch",
		&slimv1.LabelSelector{MatchLabels: map[string]string{nodegroupLabel: "does-not-exist"}},
		[]string{})
}

// TestNodeSelectorRelabel exercises the Node watch: relabelling a node loads or
// unloads a nodeSelector-gated policy on that node's agent at runtime.
func TestNodeSelectorRelabel(t *testing.T) {
	if skipReason != "" {
		t.Skip(skipReason)
	}
	const name = "node-selector-relabel-a"
	policyYAML := nodeSelectorPolicy(t, name, &slimv1.LabelSelector{MatchLabels: map[string]string{nodegroupLabel: "a"}})

	// Best-effort restore of the labels and policy this test mutates, even if an
	// assessment fails (the suite runs with -fail-fast, which skips Teardown).
	var cfg *envconf.Config
	t.Cleanup(func() {
		if cfg == nil {
			return
		}
		_ = labelNode(context.Background(), cfg, nodeA, nodegroupLabel, "a")
		_ = labelNode(context.Background(), cfg, nodeB, nodegroupLabel, "b")
		_, _ = helpers.UnloadCRDString("", policyYAML, false)(context.Background(), cfg)
	})

	feat := features.New("nodeSelector runtime relabel").
		Assess("install (loads on nodegroup=a node only)", func(ctx context.Context, t *testing.T, c *envconf.Config) context.Context {
			cfg = c
			ctx, err := helpers.LoadCRDString("", policyYAML, false)(ctx, c)
			require.NoError(t, err)
			require.NoError(t, waitPolicyOnNode(ctx, c, name, nodeA, true, 30))
			require.NoError(t, waitPolicyOnNode(ctx, c, name, nodeB, false, 10))
			return ctx
		}).
		Assess("relabel node B -> a (now loads there too)", func(ctx context.Context, t *testing.T, c *envconf.Config) context.Context {
			require.NoError(t, labelNode(ctx, c, nodeB, nodegroupLabel, "a"))
			require.NoError(t, waitPolicyOnNode(ctx, c, name, nodeB, true, 30),
				"relabelled node must load the policy")
			require.NoError(t, waitPolicyOnNode(ctx, c, name, nodeA, true, 10),
				"originally-matching node must stay loaded")
			return ctx
		}).
		Assess("remove label from node A (unloads there)", func(ctx context.Context, t *testing.T, c *envconf.Config) context.Context {
			require.NoError(t, labelNode(ctx, c, nodeA, nodegroupLabel, ""))
			require.NoError(t, waitPolicyOnNode(ctx, c, name, nodeA, false, 30),
				"node that no longer matches must unload the policy")
			require.NoError(t, waitPolicyOnNode(ctx, c, name, nodeB, true, 10),
				"still-matching node must stay loaded")
			return ctx
		}).
		Assess("restore labels + uninstall", func(ctx context.Context, t *testing.T, c *envconf.Config) context.Context {
			require.NoError(t, labelNode(ctx, c, nodeA, nodegroupLabel, "a"))
			require.NoError(t, labelNode(ctx, c, nodeB, nodegroupLabel, "b"))
			ctx, err := helpers.UnloadCRDString("", policyYAML, false)(ctx, c)
			require.NoError(t, err)
			return ctx
		}).
		Feature()

	runner.Test(t, feat)
}
