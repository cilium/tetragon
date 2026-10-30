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
	"github.com/cilium/tetragon/pkg/testutils/policytest/k8srunner"
)

type k8sFlags struct {
	enabled bool
	conf    k8srunner.Conf
	set     *pflag.FlagSet
}

func (f *k8sFlags) register(flags *pflag.FlagSet) {
	f.set = pflag.NewFlagSet("k8s", pflag.ContinueOnError)
	f.set.BoolVar(&f.enabled, "k8s", false, "run the tests in a Job on a Kubernetes cluster, next to the node-local agent")
	f.set.StringVar(&f.conf.KubeContext, "k8s-context", "", "kubeconfig context for --k8s; empty uses the current context")
	f.set.StringArrayVar(&f.conf.ExtraArgs, "k8s-arg", nil, "extra argument for the tetra policytest run in the --k8s Job; repeatable")
	f.set.StringVar(&f.conf.Image, "image", k8srunner.DefaultImage, "tester-progs image for --k8s (make image-tester-progs)")
	f.set.StringVar(&f.conf.Node, "node", "", "node to run the --k8s Job on; empty lets the scheduler pick one")
	f.set.StringVar(&f.conf.Namespace, "namespace", "tetragon-policytest", "namespace for the --k8s Job, created if missing")
	flags.AddFlagSet(f.set)
}

// check refuses the flags of the other mode.
func (f *k8sFlags) check(local *pflag.FlagSet) error {
	other, verdict := f.set, "requires --k8s"
	if f.enabled {
		other, verdict = local, "cannot be used with --k8s"
	}
	var err error
	other.VisitAll(func(fl *pflag.Flag) {
		if err == nil && fl.Changed && fl.Name != "k8s" {
			err = fmt.Errorf("--%s %s", fl.Name, verdict)
		}
	})
	return err
}

func (f *k8sFlags) runner(ctx context.Context, log *slog.Logger, timeout time.Duration, logs io.Writer) (policytest.Runner, error) {
	conf := f.conf
	conf.Timeout = timeout
	conf.Logs = logs
	return k8srunner.New(ctx, log, &conf)
}
