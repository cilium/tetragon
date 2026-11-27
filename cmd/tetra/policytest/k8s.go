// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows && !nok8s

package policytest

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/testutils/policytest"
	"github.com/cilium/tetragon/pkg/testutils/policytest/k8srunner"
)

func addK8sRunCmd(parent *cobra.Command) {
	parent.AddCommand(k8sRunCmd())
}

func k8sRunCmd() *cobra.Command {
	var conf k8srunner.Conf
	var sel policytest.Selection
	outputFile := ""
	outputFmt, _ := option.NewEnum([]string{policytest.OutputText, policytest.OutputJSON}, policytest.OutputText)
	cmd := cobra.Command{
		Use:   "k8s-run [<test-regexp>...]",
		Short: "Run Tetragon policy test(s) in a Job on a Kubernetes cluster",
		Long: "Run Tetragon policy test(s) in a Job on a Kubernetes cluster, next to the node-local agent.\n\n" +
			"The Job runs `tetra policytest run` from the tester-progs image. " +
			"The arguments select the tests as for run.",
		RunE: func(cmd *cobra.Command, args []string) error {
			log := newLogger()

			sel.Names = args
			tests, err := sel.Tests(policytest.AllPolicyTests)
			if err != nil {
				return err
			}
			conf.Timeout = time.Minute * time.Duration(sel.Runs(tests))
			conf.Logs = cmd.ErrOrStderr()

			out, closeOut, err := openOutput(cmd.OutOrStdout(), outputFile)
			if err != nil {
				return err
			}
			defer closeOut()

			// cancel on a signal, so that the Job goes
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			runner, err := k8srunner.New(ctx, log, &conf)
			if err != nil {
				return err
			}
			defer runner.Close()

			results, err := runner.Run(ctx, log, &sel)
			summary := policytest.NewResultsSummary()
			for _, res := range results {
				summary.Update(res.Result)
			}
			return errors.Join(err, policytest.WriteResults(out, outputFmt.Value, results), summary.Err())
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&conf.KubeContext, "k8s-context", "", "kubeconfig context; empty uses the current context")
	flags.StringArrayVar(&conf.ExtraArgs, "k8s-arg", nil, "extra argument for the tetra policytest run in the Job; repeatable")
	flags.StringVar(&conf.Image, "image", k8srunner.DefaultImage, "tester-progs image (make image-tester-progs)")
	flags.StringVar(&conf.Node, "node", "", "node to run the Job on; empty lets the scheduler pick one")
	flags.StringVar(&conf.Namespace, "namespace", "tetragon-policytest", "namespace for the Job, created if missing")
	flags.Var(outputFmt, "output", "output format "+outputFmt.Allowed())
	flags.StringVar(&outputFile, "output-file", "", "file to save the tests output. If empty, stdout is used.")
	sel.AddFlags(flags)
	return &cmd
}
