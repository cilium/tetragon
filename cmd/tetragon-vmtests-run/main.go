// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/little-vm-helper/pkg/arch"
	"github.com/cilium/little-vm-helper/pkg/runner"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

func main() {
	var rcnf RunConf
	var ports []string

	cmd := &cobra.Command{
		Use:          "vmtest-run",
		Short:        "vmtest-run: helper to run tetragon unit tests on VMs",
		SilenceUsage: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			log := logrus.New()
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
				rcnf.filesystems = append(rcnf.filesystems,
					&virtIOFilesystem{
						id:      "tetragon",
						hostdir: cwd,
						vmdir:   cwd,
					},
				)
				rcnf.testerConf.TetragonDir = cwd
				testingDir := filepath.Join(cwd, "tests", "vmtests")
				rcnf.testerOut = filepath.Join(testingDir, "tester-tetragon.out")
				// NB: this is awkward, but if the user just
				// wants to build an image or use an existing
				// image to run tests, using a random results
				// dir will not work.
				if !rcnf.justBuildImage && !rcnf.dontRebuildImage {
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
			if err != nil || rcnf.justBuildImage {
				return err
			}

			qemuBin, err := arch.QemuBinary()
			if err != nil {
				return fmt.Errorf("failed to get qemu binary: %w", err)
			}

			qemuArgs, err := buildQemuArgs(log, rcnf)
			if err != nil {
				return fmt.Errorf("failed to build qemu args: %w", err)
			}

			if rcnf.qemuPrint {
				var sb strings.Builder
				sb.WriteString(qemuBin)
				for _, arg := range qemuArgs {
					sb.WriteString(" ")
					if len(arg) > 0 && arg[0] == '-' {
						sb.WriteString("\\\n\t")
					}
					sb.WriteString(arg)
				}

				fmt.Printf("%s\n", sb.String())
				return nil
			}

			// if we don't need to run tests, just exec() so that user will be able to
			// login to the VM.
			if rcnf.justBoot {
				bin := filepath.Join("/usr/bin/", qemuBin)
				args := []string{qemuBin}
				args = append(args, qemuArgs...)
				env := []string{}
				return unix.Exec(bin, args, env)
			}

			results, err := runTests(&rcnf, qemuBin, qemuArgs)
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

	cmd.Flags().StringVar(&rcnf.baseImageFilename, "base", "", "base image filename")
	cmd.MarkFlagRequired("base")
	cmd.Flags().StringVar(&rcnf.vmName, "name", "tetragon", "new vm (and basis for the image name). New vm image will be in the directory of the base image")
	cmd.Flags().StringVar(&rcnf.KernelFname, "kernel", "", "kernel filename to boot with. (if empty no -kernel option will be passed to qemu)")
	cmd.Flags().BoolVar(&rcnf.dontRebuildImage, "dont-rebuild-image", false, "dont rebuild image")
	cmd.Flags().BoolVar(&rcnf.useTetragonTesterInit, "use-tetragon-init", false, "use tetragon-vmtests-init as init process in the VM")
	cmd.Flags().BoolVar(&rcnf.qemuPrint, "qemu-cmd-print", false, "Do not run the qemu command, just print it")
	cmd.Flags().BoolVar(&rcnf.DisableKVM, "qemu-disable-kvm", false, "Do not use KVM acceleration, even if /dev/kvm exists")
	cmd.Flags().BoolVar(&rcnf.justBoot, "just-boot", false, "Do not actually run any tests. Just setup everything and start the VM. User will be able to login to the VM.")
	cmd.Flags().BoolVar(&rcnf.justBuildImage, "just-build-image", false, "Just build an image. Do not actually run any tests or boot the VM.")
	cmd.Flags().BoolVar(&rcnf.testerConf.NoPowerOff, "no-poweroff", false, "Do not poweroff the VM at the end of the run")
	cmd.Flags().StringVar(&rcnf.testerConf.TestsFile, "testsfile", "", "list of tests to run")
	cmd.Flags().StringVar(&rcnf.btfFile, "btf-file", "", "BTF file to use.")
	cmd.Flags().BoolVar(&rcnf.testerConf.FailFast, "fail-fast", false, "Exit as soon as an error is encountered.")
	cmd.Flags().BoolVar(&rcnf.keepAllLogs, "keep-all-logs", false, "Normally, logs are kept only for failed tests. This switch keeps all logs.")
	cmd.Flags().BoolVar(&rcnf.disableUnifiedCgroups, "disable-unified-cgroups", false, "boot with systemd.unified_cgroup_hierarchy=0.")
	cmd.Flags().StringArrayVarP(&ports, "port", "p", nil, "Forward a port (hostport[:vmport[:tcp|udp]])")
	cmd.Flags().StringVar(&rcnf.testerConf.KernelVer, "kernel-ver", "", "kenel version")
	cmd.Flags().BoolVar(&rcnf.detailedResults, "enable-detailed-results", false, "produce detailed results")
	cmd.Flags().StringVar(&rcnf.RootDev, "root-dev", "vda", "type of root device (hda or vda)")

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
