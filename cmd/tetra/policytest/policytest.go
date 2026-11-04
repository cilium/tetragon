// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
		runMultiCmd(),
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
	flags.StringVar(&dumpPolicyPath, "dump-policy-path", dumpPolicyPath, "save the policies in the provided directory, one <policy-name>.yaml file per policy")
	sel.AddFlags(flags)
	return &cmd
}

func runCmd() *cobra.Command {
	cwd, _ := os.Getwd()
	testBinsPath := filepath.Join(cwd, "contrib/tester-progs")
	dumpPolicyPath := ""
	allTests := false
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
			log := newLogger()

			if allTests {
				return errors.New("--all-tests is deprecated. Use .* regex pattern instead")
			}

			if err := k8s.check(local); err != nil {
				return err
			}

			sel.Names = args
			tests, err := sel.Tests(policytest.AllPolicyTests)
			if err != nil {
				return err
			}

			timeout := time.Minute * time.Duration(sel.Runs(tests))

			out, closeOut, err := openOutput(cmd.OutOrStdout(), outputFile)
			if err != nil {
				return err
			}
			defer closeOut()

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()

			var runner policytest.Runner
			if k8s.enabled {
				runner, err = k8s.runner(ctx, log, timeout, cmd.ErrOrStderr())
			} else {
				runner, err = newRunner(ctx, log, testBinsPath, dumpPolicyPath, podSelector, timeout)
			}
			if err != nil {
				return err
			}
			defer runner.Close()

			return policytest.WriteResults(out, outputFmt.Value, runner.Run(ctx, log, &sel))
		},
	}
	local.StringVar(&testBinsPath, "bindir", testBinsPath, "path for test binaries directory")
	local.StringVar(&dumpPolicyPath, "dump-policy-path", dumpPolicyPath, "save the policies in the provided directory, one <policy-name>.yaml file per policy")
	local.StringToStringVar(&podSelector, "pod-selector", map[string]string{}, "scope every policy to pods with these labels (sets spec.podSelector; needs the agent's policy filter)")
	flags := cmd.Flags()
	flags.AddFlagSet(local)
	k8s.register(flags)
	flags.Var(outputFmt, "output", "output format "+outputFmt.Allowed())
	flags.StringVar(&outputFile, "output-file", "", "file to save the tests output. If empty, stdout is used.")
	// --all-tests is deprecated. TODO: remove in 1.9
	flags.BoolVar(&allTests, "all-tests", false, "Run all available policy tests.")
	flags.MarkHidden("all-tests")
	sel.AddFlags(flags)
	return &cmd
}

func runMultiCmd() *cobra.Command {
	cwd, _ := os.Getwd()
	testBinsPath := filepath.Join(cwd, "contrib/tester-progs")
	dumpPolicyPath := ""
	monitorMode := false
	allTests := false
	var params map[string]string
	var outputFile = ""
	outputFmt, _ := option.NewEnum([]string{"text", "json"}, "text")
	cmd := cobra.Command{
		Use:   "run-multi [<test-regexp>...]",
		Short: "Run multiple Tetragon policy tests with all their policies loaded at the same time",
		Long: `Run multiple Tetragon policy tests.

Each argument is a regular expression that has to match the whole test name (e.g., 'uprobe-.*'
runs all tests whose name starts with 'uprobe-'). The passed regex gets automatically anchored to
both start and end of string.

The policies of all tests are loaded first, then the scenarios of all tests are executed, and
finally the policies are unloaded.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			log := newLogger()

			if allTests {
				return errors.New("--all-tests is deprecated. Use .* regex pattern instead")
			}

			// NB: parameters are applied to all policies
			paramValues := make(map[string]any)
			for k, v := range params {
				paramValues[k] = v
			}

			ctx := context.Background()
			tests, err := (&policytest.Selection{Names: args}).Tests(policytest.AllPolicyTests)
			if err != nil {
				return err
			}
			runs := make([]localrunner.TestRun, 0, len(tests))
			results := make([]*policytest.NamedResult, 0, len(tests))
			for _, t := range tests {
				runs = append(runs, localrunner.TestRun{
					Test: t,
					// each run needs its own TestConf
					Conf: &policytest.TestConf{
						MonitorMode: monitorMode,
						ParamValues: paramValues,
					},
				})
				results = append(results, &policytest.NamedResult{
					Name: fmt.Sprintf("%s (%s)", t.Name, policytest.ParamVals(paramValues)),
				})
			}

			runner, err := newRunner(
				ctx, log, testBinsPath, dumpPolicyPath, nil, time.Minute*time.Duration(len(tests)),
			)
			if err != nil {
				return err
			}
			runResults := runner.RunTests(log, runs)
			runner.Close()

			summary := policytest.NewResultsSummary()
			for i, res := range runResults {
				results[i].Result = res
				summary.Update(res)
			}

			out, closeOut, err := openOutput(cmd.OutOrStdout(), outputFile)
			if err != nil {
				return err
			}
			defer closeOut()
			if err := writeResults(out, outputFmt.Value, results); err != nil {
				return err
			}
			return summary.Err()
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&testBinsPath, "bindir", testBinsPath, "path for test binaries directory")
	flags.StringVar(&dumpPolicyPath, "dump-policy-path", dumpPolicyPath, "save the policies in the provided directory, one <policy-name>.yaml file per policy")
	flags.BoolVar(&monitorMode, "monitor-mode", monitorMode, "set the policy(-ies) in monitor mode before running the test(s)")
	flags.StringToStringVar(&params, "set-param", map[string]string{}, "Set a policy parameter")
	flags.Var(outputFmt, "output", "output format "+outputFmt.Allowed())
	flags.StringVar(&outputFile, "output-file", "", "file to save the tests output. If empty, stdout is used.")
	// --all-tests is deprecated. TODO: remove in 1.9
	flags.BoolVar(&allTests, "all-tests", false, "Run all available policy tests.")
	flags.MarkHidden("all-tests")
	return &cmd
}

func newLogger() *slog.Logger {
	logLevel := slog.LevelInfo
	if common.Debug {
		logLevel = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(
		os.Stderr,
		&slog.HandlerOptions{
			Level: logLevel,
		},
	))
}

// newRunner creates a local runner
func newRunner(
	ctx context.Context,
	log *slog.Logger,
	testBinsPath, dumpPolicyPath string,
	podSelector map[string]string,
	timeout time.Duration,
) (*localrunner.Runner, error) {
	runner, err := localrunner.New(ctx, log, &policytest.Conf{
		GrpcAddr:        common.ServerAddress,
		BinsDir:         testBinsPath,
		DumpPolicyPath:  dumpPolicyPath,
		Timeout:         timeout,
		ScenarioTimeout: time.Minute,
		PodSelector:     podSelector,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to start local runner: %w", err)
	}
	return runner, nil
}

// openOutput returns outputFile opened for writing, or stdout if outputFile is empty. The returned
// function closes the output.
func openOutput(stdout io.Writer, outputFile string) (io.Writer, func(), error) {
	if outputFile == "" {
		return stdout, func() {}, nil
	}
	f, err := os.OpenFile(outputFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return nil, nil, fmt.Errorf("error opening output file: %w", err)
	}
	return f, func() { f.Close() }, nil
}

// writeResults writes the results to out in the given format ("json" or "text")
func writeResults(out io.Writer, format string, results []*policytest.NamedResult) error {
	switch format {
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
	return nil
}
