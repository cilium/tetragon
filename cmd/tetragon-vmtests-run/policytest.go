// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package main

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
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
	// CI runs every parameter set
	sel := policytest.Selection{AllParams: true}

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
			cnf.Console = cmd.OutOrStdout()

			// the tetra in the VM resolves the names against its registry
			sel.Names = args
			sel.AllTests = sel.AllTests || len(args) == 0
			tests := &sel
			if cnf.JustBoot {
				tests = nil
			}

			ctx, cancel := signal.NotifyContext(context.Background(), unix.SIGINT, unix.SIGTERM)
			defer cancel()

			vm, err := vmrunner.New(ctx, log, &cnf)
			if err != nil {
				return err
			}
			defer vm.Close()

			switch {
			case cnf.JustBuildImage:
				return vm.Build(tests)
			case cnf.QemuPrint:
				if err := vm.Build(tests); err != nil {
					return err
				}
				lvh.QemuPrintCmd(vm.Qemu())
				return nil
			case cnf.JustBoot:
				if err := vm.Build(tests); err != nil {
					return err
				}
				return lvh.QemuJustBoot(vm.Qemu())
			}

			return policytest.WriteResults(cmd.OutOrStdout(), policytest.OutputText, vm.Run(ctx, log, tests))
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
	sel.AddFlags(cmd.Flags())
	return cmd
}
