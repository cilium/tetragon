// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/spf13/cobra"

	"github.com/cilium/tetragon/pkg/option"

	"github.com/cilium/tetragon/cmd/tetra/common"
	"github.com/cilium/tetragon/pkg/testutils/policytest"
	"github.com/cilium/tetragon/pkg/testutils/policytest/k8sjob"
	_ "github.com/cilium/tetragon/tests/policytests" // so that tests can be registered
)

func New() *cobra.Command {
	tpCmd := &cobra.Command{
		Use:     "policytest",
		Aliases: []string{"pt"},
		Short:   "Tetragon policy tests",
	}
	tpCmd.AddCommand(
		listCmd(),
		runCmd(),
		dumpPolicyCmd(),
	)
	return tpCmd
}

func listCmd() *cobra.Command {
	listParams := false
	cmd := cobra.Command{
		Use:   "list",
		Short: "list Tetragon policy tests",
		RunE: func(cmd *cobra.Command, _ []string) error {
			for i := range policytest.AllPolicyTests.Len() {
				pt := policytest.AllPolicyTests.Get(i)
				cmd.Printf("%s %v\n", pt.Name, pt.Labels)
				if listParams && len(pt.Params) > 0 {
					cmd.Println(" parameters:")
					for _, param := range pt.Params {
						cmd.Printf("   %s\n", param.HelpString())
					}
				}
			}
			return nil
		},
	}
	flags := cmd.Flags()
	flags.BoolVar(&listParams, "list-params", listParams, "list parameters for each policy")
	return &cmd
}

func dumpPolicyCmd() *cobra.Command {
	cwd, _ := os.Getwd()
	testBinsPath := filepath.Join(cwd, "contrib/tester-progs")
	dumpPolicyPath := ""
	monitorMode := false
	var params map[string]string

	cmd := cobra.Command{
		Use:   "dump-policy",
		Short: "Dump policies from Tetragon policy test(s)",
		RunE: func(cmd *cobra.Command, args []string) error {
			// NB: parameters are applied to all policies
			paramValues := make(map[string]any)
			for k, v := range params {
				paramValues[k] = v
			}

			names := make(map[string]struct{})
			for _, arg := range args {
				names[arg] = struct{}{}
			}
			tests := policytest.AllPolicyTests.GetByFunction(func(t *policytest.T) bool {
				_, ok := names[t.Name]
				return ok
			})

			conf := policytest.Conf{
				GrpcAddr:       common.ServerAddress,
				BinsDir:        testBinsPath,
				DumpPolicyPath: dumpPolicyPath,
				TestConf: &policytest.TestConf{
					MonitorMode: monitorMode,
					ParamValues: paramValues,
				},
			}

			for _, t := range tests {
				pol, cleanup, err := t.Policy(&conf)
				if err != nil {
					return err
				}
				cmd.OutOrStdout().Write([]byte(pol))
				cleanup()
			}
			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&testBinsPath, "bindir", testBinsPath, "path for test binaries directory")
	flags.StringVar(&dumpPolicyPath, "dump-policy-path", dumpPolicyPath, "save the policy in the provided path")
	flags.BoolVar(&monitorMode, "monitor-mode", monitorMode, "set the policy(-ies) in monitor mode before running the test(s)")
	flags.StringToStringVar(&params, "set-param", map[string]string{}, "Set a policy parameter")
	return &cmd
}

func runCmd() *cobra.Command {
	cwd, _ := os.Getwd()
	testBinsPath := filepath.Join(cwd, "contrib/tester-progs")
	dumpPolicyPath := ""
	monitorMode := false
	allParams := false
	allTests := false
	var params map[string]string
	var podSelector map[string]string
	var outputFile = ""
	inK8s := false
	kubeContext := ""
	k8sOpts := k8sjob.Opts{}
	outputFmt, _ := option.NewEnum([]string{"text", "json"}, "text")
	cmd := cobra.Command{
		Use:   "run",
		Short: "Run Tetragon policy test(s)",
		Long:  "Run Tetragon policy test(s)",
		RunE: func(cmd *cobra.Command, args []string) error {
			logLevel := slog.LevelInfo
			if common.Debug {
				logLevel = slog.LevelDebug
			}
			log := slog.New(slog.NewTextHandler(
				os.Stderr,
				&slog.HandlerOptions{
					Level: logLevel,
				},
			))

			var getParamValues func(t *policytest.T) iter.Seq[policytest.ParamVals]
			if len(params) > 0 && allParams {
				return errors.New("setting --params conflicts with --all-params")
			} else if allParams {
				getParamValues = func(t *policytest.T) iter.Seq[policytest.ParamVals] {
					return t.AllParamValues()
				}
			} else {
				// NB: parameters are applied to all policies
				paramValues := make(map[string]any)
				for k, v := range params {
					paramValues[k] = v
				}
				getParamValues = func(_ *policytest.T) iter.Seq[policytest.ParamVals] {
					return func(yield func(policytest.ParamVals) bool) {
						yield(paramValues)
					}
				}
			}

			if inK8s {
				for _, f := range []string{"bindir", "dump-policy-path", "pod-selector"} {
					if cmd.Flags().Changed(f) {
						return fmt.Errorf("--%s cannot be used with --k8s", f)
					}
				}
			} else if cmd.Flags().Changed("k8s-context") {
				return errors.New("--k8s-context requires --k8s")
			}

			var ptFilterFn func(t *policytest.T) bool
			if allTests {
				ptFilterFn = func(_ *policytest.T) bool {
					return true
				}
			} else {
				names := make(map[string]struct{})
				for _, arg := range args {
					names[arg] = struct{}{}
				}
				ptFilterFn = func(t *policytest.T) bool {
					_, ok := names[t.Name]
					return ok
				}
			}
			tests := policytest.AllPolicyTests.GetByFunction(ptFilterFn)
			for _, arg := range args {
				if !slices.ContainsFunc(tests, func(t *policytest.T) bool { return t.Name == arg }) {
					return fmt.Errorf("unknown policy test %q, see `tetra policytest list`", arg)
				}
			}
			timeout := time.Minute * time.Duration(len(tests))

			out := cmd.OutOrStdout()
			if outputFile != "" {
				f, err := os.OpenFile(outputFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
				if err != nil {
					return fmt.Errorf("error opening output file: %w", err)
				}
				defer f.Close()
				out = f
			}

			if inK8s {
				k8sOpts.Args = podArgs(args, allTests, allParams, monitorMode, params, outputFmt.Value)
				k8sOpts.Timeout = timeout
				return runK8s(out, kubeContext, k8sOpts)
			}

			ctx := context.Background()
			runner, err := policytest.NewLocalRunner(ctx, log, &policytest.Conf{
				GrpcAddr:        common.ServerAddress,
				BinsDir:         testBinsPath,
				DumpPolicyPath:  dumpPolicyPath,
				Timeout:         timeout,
				ScenarioTimeout: time.Minute,
				PodSelector:     podSelector,
			})
			if err != nil {
				return fmt.Errorf("failed to start local runner: %w", err)
			}

			summary := policytest.NewResultsSummary()
			var results []*policytest.NamedResult
			for _, t := range tests {
				for paramValues := range getParamValues(t) {
					res := &policytest.NamedResult{
						Name: fmt.Sprintf("%s (%s)", t.Name, paramValues),
					}
					res.Result = runner.RunTest(log, t, &policytest.TestConf{
						MonitorMode: monitorMode,
						ParamValues: paramValues,
					})
					summary.Update(res.Result)
					results = append(results, res)
				}
			}
			runner.Close()

			switch outputFmt.Value {
			case "json":
				for _, res := range results {
					b, err := json.Marshal(res)
					if err != nil {
						return fmt.Errorf("failed to generate json: %w", err)
					}
					fmt.Fprintln(out, string(b))
				}
			case "text":
				policytest.DumpResults(out, results)
			}
			return summary.Err()
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&testBinsPath, "bindir", testBinsPath, "path for test binaries directory")
	flags.StringVar(&dumpPolicyPath, "dump-policy-path", dumpPolicyPath, "save the policy in the provided path")
	flags.BoolVar(&monitorMode, "monitor-mode", monitorMode, "set the policy(-ies) in monitor mode before running the test(s)")
	flags.StringToStringVar(&params, "set-param", map[string]string{}, "Set a policy parameter")
	flags.StringToStringVar(&podSelector, "pod-selector", map[string]string{}, "scope every policy to pods with these labels (sets spec.podSelector; needs the agent's policy filter)")
	flags.BoolVar(&allParams, "all-params", allParams, "Run policy tests using all available parameters")
	flags.Var(outputFmt, "output", "output format "+outputFmt.Allowed())
	flags.StringVar(&outputFile, "output-file", "", "file to save the tests output. If empty, stdout is used.")
	flags.BoolVar(&allTests, "all-tests", allTests, "Run all available policy tests")
	flags.BoolVar(&inK8s, "k8s", inK8s, "run the tests in a Job on a Kubernetes cluster, next to the node-local agent")
	flags.StringVar(&kubeContext, "k8s-context", "", "kubeconfig context for --k8s; empty uses the current context")
	flags.StringVar(&k8sOpts.Image, "image", "cilium/tetragon-tester-progs:latest", "tester-progs image for --k8s (make image-tester-progs)")
	flags.StringVar(&k8sOpts.Node, "node", "", "node to run the --k8s Job on; empty lets the scheduler pick one")
	flags.StringVar(&k8sOpts.Namespace, "namespace", "tetragon-policytest", "namespace for the --k8s Job, created if missing")
	return &cmd
}

func podArgs(tests []string, allTests, allParams, monitorMode bool, params map[string]string, output string) []string {
	ret := []string{"--output=" + output}
	if allTests {
		ret = append(ret, "--all-tests")
	}
	if allParams {
		ret = append(ret, "--all-params")
	}
	if monitorMode {
		ret = append(ret, "--monitor-mode")
	}
	for _, k := range slices.Sorted(maps.Keys(params)) {
		ret = append(ret, "--set-param="+k+"="+params[k])
	}
	return append(append(ret, "--"), tests...)
}
