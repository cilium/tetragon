// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/cilium/tetragon/pkg/testutils/policytest"
	"github.com/cilium/tetragon/pkg/testutils/policytest/kube"
)

const defaultKubeTimeout = 5 * time.Minute

var (
	errNoTests      = errors.New("no policy test name(s) provided")
	errUnknownTests = errors.New("unknown policy test name(s)")
	errTestsFailed  = errors.New("one or more policy tests failed")
)

// validateTests fails fast if any requested name is not a registered test, so
// `run --kube badname` errors locally instead of deploying a pod that runs
// nothing and reports success.
func validateTests(names []string) error {
	var unknown []string
	for _, name := range names {
		if len(policytest.AllPolicyTests.GetByName(name)) == 0 {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		return fmt.Errorf("%w: %s", errUnknownTests, strings.Join(unknown, ", "))
	}
	return nil
}

// kubeOpts holds the inputs for building the test pod spec.
type kubeOpts struct {
	namespace string
	image     string
	agentPort int
}

func (o *kubeOpts) podSpec(runID string, agent *kube.Agent, tests []string) *kube.TestPodSpec {
	return &kube.TestPodSpec{
		Name:      "policytest-" + runID,
		Namespace: o.namespace,
		Node:      agent.Node,
		Image:     o.image,
		RunID:     runID,
		AgentAddr: fmt.Sprintf("%s:%d", agent.PodIP, o.agentPort),
		Tests:     tests,
	}
}

func anyFailed(results []kube.TestResult) bool {
	for _, r := range results {
		if r.Failed() {
			return true
		}
	}
	return false
}

func newRunID() (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate run id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// kubeFlags holds the flags for running policy tests on a Kubernetes cluster
// (the `run --kube` mode).
type kubeFlags struct {
	opts           kubeOpts
	node           string
	agentNamespace string
	agentSelector  string
	kubeconfig     string
	timeout        time.Duration
}

func defaultKubeFlags() kubeFlags {
	return kubeFlags{
		opts: kubeOpts{
			namespace: "default",
			image:     kube.DefaultImage,
			agentPort: 54321,
		},
		agentNamespace: "kube-system",
		agentSelector:  kube.DefaultAgentLabelSelector,
		timeout:        defaultKubeTimeout,
	}
}

// addKubeFlags registers the `run --kube` flags onto a flag set.
func addKubeFlags(flags *pflag.FlagSet, kf *kubeFlags) {
	flags.StringVar(&kf.opts.namespace, "namespace", kf.opts.namespace, "namespace for the test pod and namespaced policy (--kube)")
	flags.StringVar(&kf.node, "node", kf.node, "run on this node (defaults to any node with a ready Tetragon agent) (--kube)")
	flags.StringVar(&kf.opts.image, "image", kf.opts.image, "policytest image (tetra + tester-progs) (--kube)")
	flags.IntVar(&kf.opts.agentPort, "agent-port", kf.opts.agentPort, "Tetragon agent gRPC port (--kube)")
	flags.StringVar(&kf.agentNamespace, "agent-namespace", kf.agentNamespace, "namespace where the Tetragon agent runs (--kube)")
	flags.StringVar(&kf.agentSelector, "agent-selector", kf.agentSelector, "label selector for Tetragon agent pods (--kube)")
	flags.StringVar(&kf.kubeconfig, "kubeconfig", kf.kubeconfig, "path to kubeconfig (defaults to the ambient configuration) (--kube)")
	flags.DurationVar(&kf.timeout, "timeout", kf.timeout, "overall timeout for the cluster run, e.g. if the test pod never completes (--kube)")
}

// runKube runs policy tests against a Tetragon install on a Kubernetes cluster:
// it discovers a node-local agent, deploys a test pod that triggers the policy
// from within the cluster, collects the results, and renders them.
func runKube(cmd *cobra.Command, args []string, kf *kubeFlags) error {
	if len(args) == 0 {
		return errNoTests
	}
	if err := validateTests(args); err != nil {
		return err
	}

	client, err := kube.NewClient(kf.kubeconfig)
	if err != nil {
		return err
	}

	ctx := context.Background()
	if kf.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, kf.timeout)
		defer cancel()
	}

	agent, err := kube.DiscoverAgent(ctx, client, kf.agentNamespace, kf.agentSelector, kf.node)
	if err != nil {
		return err
	}

	runID, err := newRunID()
	if err != nil {
		return err
	}

	spec := kf.opts.podSpec(runID, agent, args)
	orch := kube.NewOrchestrator(client, kf.opts.namespace)
	results, err := orch.Run(ctx, spec)
	if err != nil {
		return err
	}

	names, res := kube.ToResults(results)
	policytest.DumpResults(cmd.OutOrStdout(), names, res)
	if anyFailed(results) {
		return errTestsFailed
	}
	return nil
}
