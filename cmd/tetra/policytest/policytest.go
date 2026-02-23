// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (

	// import tests
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

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
	)
	return tpCmd
}

func listCmd() *cobra.Command {
	cmd := cobra.Command{
		Use:   "list",
		Short: "list Tetragon policy tests",
		RunE: func(_ *cobra.Command, _ []string) error {
			for i := range policytest.AllPolicyTests.Len() {
				pt := policytest.AllPolicyTests.Get(i)
				fmt.Printf("%s %v\n", pt.Name, pt.Labels)
			}
			return nil
		},
	}
	return &cmd
}

func runCmd() *cobra.Command {
	cwd, _ := os.Getwd()
	testBinsPath := filepath.Join(cwd, "contrib/tester-progs")
	dumpPolicyPath := ""
	monitorMode := false
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

			ctx := context.Background()
			names := make(map[string]struct{})
			for _, arg := range args {
				names[arg] = struct{}{}
			}
			tests := policytest.AllPolicyTests.GetByFunction(func(t *policytest.T) bool {
				_, ok := names[t.Name]
				return ok
			})
			runner, err := policytest.NewLocalRunner(ctx, log, &policytest.Conf{
				GrpcAddr:       common.ServerAddress,
				BinsDir:        testBinsPath,
				DumpPolicyPath: dumpPolicyPath,
			})
			if err != nil {
				return fmt.Errorf("failed to start local runner: %w", err)
			}
			var results []*policytest.Result
			var ptNames []string
			for _, t := range tests {
				ptNames = append(ptNames, t.Name)
				res := runner.RunTest(log, t, &policytest.RunConf{
					MonitorMode: monitorMode,
				})
				results = append(results, res)
			}
			runner.Close()
			policytest.DumpResults(cmd.OutOrStdout(), ptNames, results)
			return nil
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&testBinsPath, "bindir", testBinsPath, "path for test binaries directory")
	flags.StringVar(&dumpPolicyPath, "dump-policy-path", dumpPolicyPath, "save the policy in the provided path")
	flags.BoolVar(&monitorMode, "monitor-mode", monitorMode, "set the policy(-ies) in monitor mode before running the test(s)")
	return &cmd
}
