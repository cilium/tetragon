// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/cilium/tetragon/pkg/option"

	"github.com/cilium/tetragon/cmd/tetra/common"
	"github.com/cilium/tetragon/pkg/testutils/policytest"
	"github.com/cilium/tetragon/pkg/testutils/policytest/localrunner"
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
	var sel policytest.Selection

	cmd := cobra.Command{
		Use:   "dump-policy <test-regexp>...",
		Short: "Dump policies from Tetragon policy test(s)",
		Long: "Dump policies from Tetragon policy test(s).\n\n" +
			"Each argument is a regular expression that has to match the whole test name " +
			"(e.g., 'uprobe-.*' runs all tests whose name starts with 'uprobe-')." +
			"The passed regex gets automatically anchored to both start end end of string.",
		RunE: func(cmd *cobra.Command, args []string) error {
			sel.Names = args
			tests, err := sel.Tests(policytest.AllPolicyTests)
			if err != nil {
				return err
			}

			for _, t := range tests {
				for paramValues := range sel.ParamValues(t) {
					conf := policytest.Conf{
						GrpcAddr:       common.ServerAddress,
						BinsDir:        testBinsPath,
						DumpPolicyPath: dumpPolicyPath,
						TestConf: &policytest.TestConf{
							MonitorMode: sel.MonitorMode,
							ParamValues: paramValues,
						},
					}
					pol, cleanup, err := t.Policy(&conf)
					if err != nil {
						return err
					}
					cmd.OutOrStdout().Write([]byte(pol))
					cleanup()
				}
			}
			return nil
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&testBinsPath, "bindir", testBinsPath, "path for test binaries directory")
	flags.StringVar(&dumpPolicyPath, "dump-policy-path", dumpPolicyPath, "save the policy in the provided path")
	sel.AddFlags(flags)
	return &cmd
}

func runCmd() *cobra.Command {
	cwd, _ := os.Getwd()
	testBinsPath := filepath.Join(cwd, "contrib/tester-progs")
	dumpPolicyPath := ""
	var sel policytest.Selection
	var podSelector map[string]string
	var outputFile = ""
	var k8s k8sFlags
	outputFmt, _ := option.NewEnum([]string{"text", "json"}, "text")
	cmd := cobra.Command{
		Use:   "run [<test-regexp>...]",
		Short: "Run Tetragon policy test(s)",
		Long: "Run Tetragon policy test(s).\n\n" +
			"Each argument is a regular expression that has to match the whole test name " +
			"(e.g., 'uprobe-.*' runs all tests whose name starts with 'uprobe-')." +
			"The passed regex gets automatically anchored to both start end end of string.",
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

			if k8s.enabled {
				for _, f := range []string{"bindir", "dump-policy-path", "pod-selector"} {
					if cmd.Flags().Changed(f) {
						return fmt.Errorf("--%s cannot be used with --k8s", f)
					}
				}
			} else if cmd.Flags().Changed("k8s-context") {
				return errors.New("--k8s-context requires --k8s")
			}

			sel.Names = args
			tests, err := sel.Tests(policytest.AllPolicyTests)
			if err != nil {
				return err
			}

			timeout := time.Minute * time.Duration(sel.Runs(tests))

			out := cmd.OutOrStdout()
			if outputFile != "" {
				f, err := os.OpenFile(outputFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
				if err != nil {
					return fmt.Errorf("error opening output file: %w", err)
				}
				defer f.Close()
				out = f
			}

			if k8s.enabled {
				remote, err := podArgs(&sel, outputFmt.Value)
				if err != nil {
					return err
				}
				return k8s.run(out, timeout, remote)
			}

			ctx := context.Background()
			runner, err := localrunner.New(ctx, log, &policytest.Conf{
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

			defer runner.Close()

			summary := policytest.NewResultsSummary()
			for _, t := range tests {
				for paramValues := range sel.ParamValues(t) {
					res := &policytest.NamedResult{
						Name: fmt.Sprintf("%s (%s)", t.Name, paramValues),
					}
					res.Result = runner.RunTest(log, t, &policytest.TestConf{
						MonitorMode: sel.MonitorMode,
						ParamValues: paramValues,
					})
					summary.Update(res.Result)

					switch outputFmt.Value {
					case "json":
						b, err := json.Marshal(res)
						if err != nil {
							return fmt.Errorf("failed to generate json: %w", err)
						}
						fmt.Fprintln(out, string(b))
					case "text":
						policytest.DumpResults(out, []*policytest.NamedResult{res})
					}
				}
			}
			return summary.Err()
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&testBinsPath, "bindir", testBinsPath, "path for test binaries directory")
	flags.StringVar(&dumpPolicyPath, "dump-policy-path", dumpPolicyPath, "save the policy in the provided path")
	flags.StringToStringVar(&podSelector, "pod-selector", map[string]string{}, "scope every policy to pods with these labels (sets spec.podSelector; needs the agent's policy filter)")
	flags.Var(outputFmt, "output", "output format "+outputFmt.Allowed())
	flags.StringVar(&outputFile, "output-file", "", "file to save the tests output. If empty, stdout is used.")
	sel.AddFlags(flags)
	k8s.register(flags)
	return &cmd
}

// podArgs are the arguments of the tetra in the pod: the output format and
// the selection, which the pod's tetra resolves against its own registry.
func podArgs(sel *policytest.Selection, output string) ([]string, error) {
	args, err := sel.Args()
	if err != nil {
		return nil, err
	}
	return append([]string{"--output=" + output}, args...), nil
}
