// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

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
	local := pflag.NewFlagSet("local", pflag.ContinueOnError)
	outputFmt, _ := option.NewEnum([]string{policytest.OutputText, policytest.OutputJSON}, policytest.OutputText)
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

			if err := k8s.check(local); err != nil {
				return err
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

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			var runner policytest.Runner
			if k8s.enabled {
				runner, err = k8s.runner(ctx, log, timeout, cmd.ErrOrStderr())
			} else {
				runner, err = localrunner.New(ctx, log, &policytest.Conf{
					GrpcAddr:        common.ServerAddress,
					BinsDir:         testBinsPath,
					DumpPolicyPath:  dumpPolicyPath,
					Timeout:         timeout,
					ScenarioTimeout: time.Minute,
					PodSelector:     podSelector,
				})
			}
			if err != nil {
				return fmt.Errorf("failed to start runner: %w", err)
			}
			defer runner.Close()

			return policytest.WriteResults(out, outputFmt.Value, runner.Run(ctx, log, &sel))
		},
	}
	local.StringVar(&testBinsPath, "bindir", testBinsPath, "path for test binaries directory")
	local.StringVar(&dumpPolicyPath, "dump-policy-path", dumpPolicyPath, "save the policy in the provided path")
	local.StringToStringVar(&podSelector, "pod-selector", map[string]string{}, "scope every policy to pods with these labels (sets spec.podSelector; needs the agent's policy filter)")
	flags := cmd.Flags()
	flags.AddFlagSet(local)
	k8s.register(flags)
	flags.Var(outputFmt, "output", "output format "+outputFmt.Allowed())
	flags.StringVar(&outputFile, "output-file", "", "file to save the tests output. If empty, stdout is used.")
	sel.AddFlags(flags)
	return &cmd
}
