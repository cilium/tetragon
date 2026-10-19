// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/little-vm-helper/pkg/runner"
	"github.com/cilium/little-vm-helper/pkg/slogger"
	"github.com/spf13/cobra"

	"github.com/cilium/tetragon/pkg/vmtests/lvh"
)

func goTestCmd() *cobra.Command {
	var rcnf GoTestConf
	var ports []string

	cmd := &cobra.Command{
		Use:          "gotest",
		Short:        "gotest: helper to run tetragon unit tests on VMs",
		SilenceUsage: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			log := slogger.New()
			t0 := time.Now()

			var err error
			rcnf.ForwardedPorts, err = runner.ParsePortForward(ports)
			if err != nil {
				return fmt.Errorf("error parseing ports: %w", err)
			}

			// Keep all logs if user asked for it, or if user asked for detailed results
			// since we need the log files to generate them.
			if rcnf.keepAllLogs || rcnf.detailedResults {
				rcnf.testerConf.KeepAllLogs = true
			}

			// Hardcoded (for now):
			// mount cwd as cwd in the VM (this helps with contrib/test-progs paths)
			// set output to be <cwd>/tester-tetragon.out.
			if cwd, err := os.Getwd(); err == nil {
				rcnf.Filesystems = append(rcnf.Filesystems,
					&lvh.VirtIOFS{
						ID:      "tetragon",
						HostDir: cwd,
						VMDir:   cwd,
					},
				)
				rcnf.testerConf.TetragonDir = cwd
				testingDir := filepath.Join(cwd, "tests", "vmtests")
				// NB: this is awkward, but if the user just
				// wants to build an image or use an existing
				// image to run tests, using a random results
				// dir will not work.
				if !rcnf.JustBuildImage && !rcnf.DontRebuildImage {
					rcnf.testerConf.ResultsDir, err = os.MkdirTemp(testingDir, "vmtests-results-")
					if err != nil {
						return fmt.Errorf("failed to make results dir: %w", err)
					}
				} else {
					rcnf.testerConf.ResultsDir = filepath.Join(testingDir, "vmtests-results")
					err := os.MkdirAll(rcnf.testerConf.ResultsDir, 0755)
					if err != nil {
						return fmt.Errorf("failed to make results dir: %w", err)
					}
				}
			} else {
				return fmt.Errorf("failed to get cwd: %w", err)
			}

			err = buildTestImage(log, &rcnf)
			if err != nil || rcnf.JustBuildImage {
				return err
			}

			qemuBin, qemuArgs, err := lvh.QemuCommand(log, rcnf.Conf)
			if err != nil {
				return err
			}

			if rcnf.QemuPrint {
				lvh.QemuPrintCmd(qemuBin, qemuArgs)
				return nil
			}

			// if we don't need to run tests, just exec() so that user will be able to
			// login to the VM.
			if rcnf.JustBoot {
				return lvh.QemuJustBoot(qemuBin, qemuArgs)
			}

			results, err := runGoTests(&rcnf, qemuBin, qemuArgs)
			if err != nil {
				return err
			}

			dur := time.Since(t0).Round(time.Millisecond)
			if results.nrFailedTests > 0 {
				fmt.Printf("%d/%d tests failed 😞 (took: %s, skipped:%d)\n", results.nrFailedTests, results.nrTests, dur, results.nrSkipedTests)
				return errors.New("failed")
			}

			if results.nrTests == 0 {
				fmt.Printf("only 0 tests? something is 🐟\n")
				return errors.New("failed")
			}

			if results.nrSkipedTests == results.nrTests {
				fmt.Printf("All %d tests were skipped 🤔 (took: %s, skipped:%d)\n", results.nrTests, dur, results.nrSkipedTests)
				return nil
			}

			fmt.Printf("All %d tests succeeded! 🎉🚢🍕 (took: %s, skipped:%d)\n", results.nrTests, dur, results.nrSkipedTests)
			return nil
		},
	}

	lvh.AddFlags(cmd, &rcnf.Conf)
	cmd.Flags().BoolVar(&rcnf.testerConf.NoPowerOff, "no-poweroff", false, "Do not poweroff the VM at the end of the run")
	cmd.Flags().StringVar(&rcnf.testerConf.TestsFile, "testsfile", "", "list of tests to run")
	cmd.Flags().StringVar(&rcnf.BTFFile, "btf-file", "", "BTF file to use.")
	cmd.Flags().BoolVar(&rcnf.testerConf.FailFast, "fail-fast", false, "Exit as soon as an error is encountered.")
	cmd.Flags().BoolVar(&rcnf.keepAllLogs, "keep-all-logs", false, "Normally, logs are kept only for failed tests. This switch keeps all logs.")
	cmd.Flags().BoolVar(&rcnf.DisableUnifiedCgroups, "disable-unified-cgroups", false, "boot with systemd.unified_cgroup_hierarchy=0.")
	cmd.Flags().StringArrayVarP(&ports, "port", "p", nil, "Forward a port (hostport[:vmport[:tcp|udp]])")
	cmd.Flags().StringVar(&rcnf.testerConf.KernelVer, "kernel-ver", "", "kenel version")
	cmd.Flags().BoolVar(&rcnf.detailedResults, "enable-detailed-results", false, "produce detailed results")

	return cmd
}
