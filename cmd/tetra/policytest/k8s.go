// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package policytest

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/pflag"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/cilium/tetragon/pkg/testutils/policytest/k8sjob"
)

type k8sFlags struct {
	enabled bool
	context string
	opts    k8sjob.Opts
}

func (f *k8sFlags) register(flags *pflag.FlagSet) {
	flags.BoolVar(&f.enabled, "k8s", false, "run the tests in a Job on a Kubernetes cluster, next to the node-local agent")
	flags.StringVar(&f.context, "k8s-context", "", "kubeconfig context for --k8s; empty uses the current context")
	flags.StringVar(&f.opts.Image, "image", "cilium/tetragon-tester-progs:latest", "tester-progs image for --k8s (make image-tester-progs)")
	flags.StringVar(&f.opts.Node, "node", "", "node to run the --k8s Job on; empty lets the scheduler pick one")
	flags.StringVar(&f.opts.Namespace, "namespace", "tetragon-policytest", "namespace for the --k8s Job, created if missing")
}

func (f *k8sFlags) run(out io.Writer, timeout time.Duration, args []string) error {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	overrides := &clientcmd.ConfigOverrides{CurrentContext: f.context}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig()
	if err != nil {
		return fmt.Errorf("failed to load kubeconfig: %w", err)
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	opts := f.opts
	opts.Args = args
	opts.Timeout = timeout
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return k8sjob.Run(ctx, cs, opts, out)
}
