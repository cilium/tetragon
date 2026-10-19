// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/cilium/tetragon/pkg/option"

	"github.com/cilium/tetragon/cmd/tetra/common"
	"github.com/cilium/tetragon/pkg/testutils/policytest"
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

			sel := policytest.Selection{Names: args}
			tests, err := sel.Tests(policytest.AllPolicyTests)
			if err != nil {
				return err
			}

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
	var selFlags selectionFlags
	var outputFile = ""
	outputFmt, _ := option.NewEnum([]string{policytest.OutputText, policytest.OutputJSON}, policytest.OutputText)
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

			sel := selFlags.selection(args)
			tests, err := sel.Tests(policytest.AllPolicyTests)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if outputFile != "" {
				f, err := os.OpenFile(outputFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
				if err != nil {
					return fmt.Errorf("error opening output file: %w", err)
				}
				defer f.Close()
				out = f
			}

			ctx := context.Background()
			runner, err := policytest.NewLocalRunner(ctx, log, &policytest.Conf{
				GrpcAddr:        common.ServerAddress,
				BinsDir:         testBinsPath,
				DumpPolicyPath:  dumpPolicyPath,
				Timeout:         time.Minute * time.Duration(len(tests)),
				ScenarioTimeout: time.Minute,
			})
			if err != nil {
				return fmt.Errorf("failed to start local runner: %w", err)
			}
			defer runner.Close()

			return policytest.WriteResults(out, outputFmt.Value, runner.Run(ctx, log, sel))
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&testBinsPath, "bindir", testBinsPath, "path for test binaries directory")
	flags.StringVar(&dumpPolicyPath, "dump-policy-path", dumpPolicyPath, "save the policy in the provided path")
	flags.Var(outputFmt, "output", "output format "+outputFmt.Allowed())
	flags.StringVar(&outputFile, "output-file", "", "file to save the tests output. If empty, stdout is used.")
	selFlags.register(flags)
	return &cmd
}

// selectionFlags are the run flags that pick the tests and how to run them.
type selectionFlags struct {
	allTests    bool
	allParams   bool
	monitorMode bool
	params      map[string]string
}

func (f *selectionFlags) register(flags *pflag.FlagSet) {
	flags.BoolVar(&f.allTests, "all-tests", false, "Run all available policy tests")
	flags.BoolVar(&f.allParams, "all-params", false, "Run policy tests using all available parameters")
	flags.BoolVar(&f.monitorMode, "monitor-mode", false, "set the policy(-ies) in monitor mode before running the test(s)")
	flags.StringToStringVar(&f.params, "set-param", map[string]string{}, "Set a policy parameter")
}

func (f *selectionFlags) selection(names []string) *policytest.Selection {
	return &policytest.Selection{
		Names:       names,
		AllTests:    f.allTests,
		Params:      f.params,
		AllParams:   f.allParams,
		MonitorMode: f.monitorMode,
	}
}
