// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package policytest

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/spf13/pflag"

	"github.com/cilium/tetragon/pkg/testutils/policytest"
)

type k8sFlags struct {
	enabled bool
	conf    policytest.K8sConf
}

func (f *k8sFlags) register(flags *pflag.FlagSet) {
	flags.BoolVar(&f.enabled, "k8s", false, "run the tests in a Job on a Kubernetes cluster, next to the node-local agent")
	flags.StringVar(&f.conf.KubeContext, "k8s-context", "", "kubeconfig context for --k8s; empty uses the current context")
	flags.StringArrayVar(&f.conf.ExtraArgs, "k8s-arg", nil, "extra argument for the tetra policytest run in the --k8s Job; repeatable")
	flags.StringVar(&f.conf.Image, "image", policytest.DefaultK8sImage, "tester-progs image for --k8s (make image-tester-progs)")
	flags.StringVar(&f.conf.Node, "node", "", "node to run the --k8s Job on; empty lets the scheduler pick one")
	flags.StringVar(&f.conf.Namespace, "namespace", "tetragon-policytest", "namespace for the --k8s Job, created if missing")
}

// check refuses the flags that belong to the other mode.
func (f *k8sFlags) check(flags *pflag.FlagSet) error {
	if f.enabled {
		for _, name := range []string{"bindir", "dump-policy-path", "pod-selector"} {
			if flags.Changed(name) {
				return fmt.Errorf("--%s cannot be used with --k8s", name)
			}
		}
		return nil
	}
	for _, name := range []string{"k8s-context", "k8s-arg", "image", "node", "namespace"} {
		if flags.Changed(name) {
			return fmt.Errorf("--%s requires --k8s", name)
		}
	}
	return nil
}

// runner returns the Runner for the cluster. logs receives the pod output
// that is not a result.
func (f *k8sFlags) runner(ctx context.Context, log *slog.Logger, timeout time.Duration, logs io.Writer) (policytest.Runner, error) {
	conf := f.conf
	conf.Timeout = timeout
	conf.Logs = logs
	return policytest.NewK8sRunner(ctx, log, &conf)
}
