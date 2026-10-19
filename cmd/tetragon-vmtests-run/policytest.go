// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"os/signal"
	"slices"

	"github.com/cilium/little-vm-helper/pkg/runner"
	"github.com/cilium/little-vm-helper/pkg/slogger"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"

	"github.com/cilium/tetragon/pkg/testutils/policytest"
	"github.com/cilium/tetragon/pkg/testutils/policytest/vmrunner"
	"github.com/cilium/tetragon/pkg/vmtests/lvh"
)

func policyTestCmd() *cobra.Command {
	var cnf vmrunner.Conf
	var ports []string
	var mountHostPath string
	var extraArgs map[string]string
	var allParams bool

	cmd := &cobra.Command{
		Use:          "policytest [test names]",
		Short:        "policytest: helper to run tetragon policytests on VMs",
		Long:         "policytest runs the policy tests in a VM. Without test names, it runs all of them.",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			log := slog.New(slogger.New().Handler())

			cnf.ForwardedPorts, err = runner.ParsePortForward(ports)
			if err != nil {
				return fmt.Errorf("error parsing ports: %w", err)
			}

			if mountHostPath != "" {
				cnf.Filesystems = append(cnf.Filesystems,
					&lvh.VirtIOFS{
						ID:      "host",
						HostDir: mountHostPath,
						VMDir:   "/host",
					},
				)
			}
			for _, k := range slices.Sorted(maps.Keys(extraArgs)) {
				cnf.ExtraArgs = append(cnf.ExtraArgs, fmt.Sprintf("--%s=%s", k, extraArgs[k]))
			}
			cnf.Logs = cmd.ErrOrStderr()
			cnf.Console = cmd.OutOrStdout()

			// the tetra in the VM resolves the names against its registry
			sel := &policytest.Selection{Names: args, AllTests: len(args) == 0, AllParams: allParams}
			if err := sel.Validate(); err != nil {
				return err
			}
			if cnf.JustBoot {
				// no tests: the user logs in to the VM
				sel = nil
			}

			ctx, cancel := signal.NotifyContext(context.Background(), unix.SIGINT, unix.SIGTERM)
			defer cancel()

			vm, err := vmrunner.NewVMRunner(ctx, log, &cnf)
			if err != nil {
				return err
			}
			defer vm.Close()

			switch {
			case cnf.JustBuildImage:
				return vm.Build(sel)
			case cnf.QemuPrint:
				if err := vm.Build(sel); err != nil {
					return err
				}
				lvh.QemuPrintCmd(vm.Qemu())
				return nil
			case cnf.JustBoot:
				if err := vm.Build(sel); err != nil {
					return err
				}
				return lvh.QemuJustBoot(vm.Qemu())
			}

			summary := policytest.NewResultsSummary()
			var results []*policytest.NamedResult
			for res, err := range vm.Run(ctx, log, sel) {
				if err != nil {
					return err
				}
				summary.Update(res.Result)
				results = append(results, res)
			}
			policytest.DumpResults(os.Stdout, results)

			if summary.Errs > 0 {
				cmd.Printf("%d/%d tests failed 😞 (skipped:%d)\n", summary.Errs, summary.Total, summary.Skipped)
				return errors.New("failed")
			}

			if summary.Skipped == summary.Total {
				cmd.Printf("All %d tests were skipped 🤔\n", summary.Total)
				return nil
			}

			cmd.Printf("No errors! 🎉🚢🍕 (total:%d skipped:%d)\n", summary.Total, summary.Skipped)
			return nil
		},
	}

	lvh.AddFlags(cmd, &cnf.Conf)
	cmd.Flags().StringVar(&cnf.TetragonInstallDir, "tetragon-dir", "", "tetragon install directory")
	cmd.Flags().StringVar(&cnf.TetragonTarball, "tetragon-tarball", "", "tetragon install tarball")
	cmd.Flags().StringVar(&cnf.TesterProgsDir, "tester-progs-dir", "", "tetragon tester progs directory")
	cmd.Flags().StringVar(&cnf.TesterProgsTarball, "tester-progs-tarball", "", "tetragon tester progs tarball")
	cmd.Flags().StringToStringVar(&cnf.Environment, "env", nil, "Set an environment variable for policytests (NAME=VALUE)")
	cmd.Flags().StringArrayVarP(&ports, "port", "p", nil, "Forward a port (hostport[:vmport[:tcp|udp]])")
	cmd.Flags().StringVar(&mountHostPath, "mount-host-path", "", "host path to mount inside VM")
	cmd.Flags().StringVar(&cnf.BTFFile, "btf-file", "", "BTF file to use.")
	cmd.Flags().StringToStringVar(&extraArgs, "policytest-extra-args", nil, "`tetra policytest` extra arguments (--key=val)")
	cmd.Flags().BoolVar(&allParams, "all-params", true, "run every test once per combination of its parameter values; set it to false to pass set-param through --policytest-extra-args")
	return cmd
}
