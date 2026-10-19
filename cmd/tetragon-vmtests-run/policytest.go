// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/little-vm-helper/pkg/arch"
	"github.com/cilium/little-vm-helper/pkg/images"
	"github.com/cilium/little-vm-helper/pkg/runner"
	"github.com/cilium/little-vm-helper/pkg/slogger"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"

	"github.com/cilium/tetragon/pkg/testutils/policytest"
	"github.com/cilium/tetragon/pkg/vmtests/lvh"
)

var (
	policytestsVmResultsDir = "/policytests-results"
)

type PolicyTestConf struct {
	lvh.Conf
	tetragonInstallDir  string
	tetragonTarball     string
	testerProgsDir      string
	testerProgsTarball  string
	resultsDir          string
	policytestExtraArgs map[string]string
	environment         map[string]string
}

func policyTestCmd() *cobra.Command {
	var cnf PolicyTestConf
	var ports []string
	var mountHostPath string

	cmd := &cobra.Command{
		Use:          "policytest",
		Short:        "policytest: helper to run tetragon policytests on VMs",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var err error
			log := slogger.New()

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

			if !cnf.JustBuildImage && !cnf.DontRebuildImage {
				cnf.resultsDir, err = os.MkdirTemp("", "policytests-results-")
				if err != nil {
					return fmt.Errorf("failed to make results dir: %w", err)
				}
				cnf.Filesystems = append(cnf.Filesystems,
					&lvh.VirtIOFS{
						ID:      "results",
						HostDir: cnf.resultsDir,
						VMDir:   policytestsVmResultsDir,
					},
				)
			}

			tmpDir, err := os.MkdirTemp("", "tetragon-policytests-")
			if err != nil {
				return err
			}
			defer os.RemoveAll(tmpDir)

			if err := cnf.MaybePullBaseImage(context.Background(), tmpDir); err != nil {
				return err
			}

			err = buildPolicyTestImage(log, &cnf, tmpDir)
			if err != nil || cnf.JustBuildImage {
				return err
			}

			runtimeArch, err := arch.NewArch(runtime.GOARCH)
			if err != nil {
				return fmt.Errorf("failed to create lvh arch: %w", err)
			}

			qemuBin := runtimeArch.QemuBinary()
			qemuArgs, err := lvh.BuildQemuArgs(log, cnf.Conf)
			if err != nil {
				return fmt.Errorf("failed to build qemu args: %w", err)
			}

			if cnf.QemuPrint {
				lvh.QemuPrintCmd(qemuBin, qemuArgs)
				return nil
			}

			// if we don't need to run tests, just exec() so that user will be able to
			// login to the VM.
			if cnf.JustBoot {
				return lvh.QemuJustBoot(qemuBin, qemuArgs)
			}

			summary, err := runPolicyTests(&cnf, qemuBin, qemuArgs)
			if err != nil {
				return err
			}

			if summary.Errs > 0 {
				cmd.Printf("%d/%d tests failed 😞 (skipped:%d)\n", summary.Errs, summary.Total, summary.Skipped)
				return errors.New("failed")
			}

			if summary.Total == 0 {
				cmd.Printf("only 0 results? something is 🐟\n")
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
	cmd.Flags().StringVar(&cnf.tetragonInstallDir, "tetragon-dir", "", "tetragon install directory")
	cmd.Flags().StringVar(&cnf.tetragonTarball, "tetragon-tarball", "", "tetragon install tarball")
	cmd.Flags().StringVar(&cnf.testerProgsDir, "tester-progs-dir", "", "tetragon tester progs directory")
	cmd.Flags().StringVar(&cnf.testerProgsTarball, "tester-progs-tarball", "", "tetragon tester progs tarball")
	cmd.Flags().StringToStringVar(&cnf.environment, "env", nil, "Set an environment variable for policytests (NAME=VALUE)")
	cmd.Flags().StringArrayVarP(&ports, "port", "p", nil, "Forward a port (hostport[:vmport[:tcp|udp]])")
	cmd.Flags().StringVar(&mountHostPath, "mount-host-path", "", "host path to mount inside VM")
	cmd.Flags().StringVar(&cnf.BTFFile, "btf-file", "", "BTF file to use.")
	cmd.Flags().StringToStringVar(&cnf.policytestExtraArgs, "policytest-extra-args", nil, "`tetra policytest` extra arguments (--key=val)")
	return cmd
}

func tarballInstallPath(tarball string) (string, error) {
	f, err := os.Open(tarball)
	if err != nil {
		return "", err
	}
	defer f.Close()
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return "", errors.New("could not find install.sh")
		}
		if err != nil {
			return "", err
		}

		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if path.Base(hdr.Name) == "install.sh" {
			return hdr.Name, nil
		}
	}
}

func decompressToTemp(fname, tmpDir string) (string, error) {
	in, err := os.Open(fname)
	if err != nil {
		return "", err
	}
	defer in.Close()

	gz, err := gzip.NewReader(in)
	if err != nil {
		return "", err
	}
	defer gz.Close()

	tmp, err := os.CreateTemp(tmpDir, "tetragon-*.tar")
	if err != nil {
		return "", err
	}

	if _, err := io.Copy(tmp, gz); err != nil {
		tmp.Close()
		os.Remove(tmp.Name()) // clean up on failure
		return "", err
	}

	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}

	return tmp.Name(), nil
}

func buildTetragonActions(ptConf *PolicyTestConf, tmpDir string) ([]images.Action, error) {
	ret := make([]images.Action, 0)

	// copy BTF file to the VM
	vmBTFFile := ""
	if btfFile := ptConf.BTFFile; btfFile != "" {
		absBTFFile, err := filepath.Abs(btfFile)
		if err != nil {
			return nil, fmt.Errorf("failed to get btf file full path: %w", err)
		}
		ret = append(ret, images.Action{
			Op: &images.CopyInCommand{
				LocalPath: absBTFFile,
				RemoteDir: "/boot/",
			},
		})
		vmBTFFile = "/boot/" + filepath.Base(btfFile)
	}

	if ptConf.tetragonInstallDir != "" && ptConf.tetragonTarball != "" {
		return nil, errors.New("you need to define exactly one of --tetragon-install-dir and --tetragon-tarball")
	} else if ptConf.tetragonInstallDir != "" {
		additionalArgs := ""
		if ptConf.BTFFile != "" {
			additionalArgs = "--btf " + vmBTFFile
		}
		service, err := lvh.TetragonServiceFile(filepath.Join(tmpDir, lvh.TetragonService), additionalArgs)
		if err != nil {
			return nil, err
		}
		ret = append(ret,
			// install.sh
			images.Action{Op: &images.CopyInCommand{
				LocalPath: filepath.Join(ptConf.tetragonInstallDir, "usr", "local"),
				RemoteDir: "/usr",
			}},
			// tetragon systemd service
			images.Action{Op: &images.CopyInCommand{
				LocalPath: service,
				RemoteDir: "/etc/systemd/system/",
			}},
			images.Action{Op: &images.RunCommand{Cmd: "systemctl enable " + lvh.TetragonService}},
		)
	} else if ptConf.tetragonTarball != "" {
		tarball := ptConf.tetragonTarball
		if strings.HasSuffix(tarball, ".gz") || strings.HasSuffix(tarball, ".tgz") {
			var err error
			tarball, err = decompressToTemp(tarball, tmpDir)
			if err != nil {
				return nil, err
			}
		}

		tetragonInstallSh, err := tarballInstallPath(tarball)
		if err != nil {
			return nil, err
		}
		remoteDir := "/tmp"
		ret = append(ret,
			images.Action{Op: &images.TarInCommand{
				TarFile:   tarball,
				RemoteDir: remoteDir,
			}},
			images.Action{Op: &images.RunCommand{Cmd: filepath.Join(remoteDir, tetragonInstallSh)}},
			images.Action{Op: &images.AppendLineCommand{
				File: "/etc/tetragon/tetragon.conf.d/btf",
				Line: vmBTFFile,
			}},
		)
	} else {
		return nil, errors.New("you need to define exactly one of --tetragon-install-dir and --tetragon-tarball")
	}

	// install tester progs
	if ptConf.testerProgsDir != "" && ptConf.testerProgsTarball != "" {
		return nil, errors.New("you need to define exactly one of --tester-progs-dir and --tetragon-progs-tarball")
	} else if ptConf.testerProgsDir != "" {
		ret = append(ret, mustCopyTesterProgsCmd(ptConf.testerProgsDir, tmpDir))
	} else if ptConf.testerProgsTarball != "" {
		tarball := ptConf.testerProgsTarball
		if strings.HasSuffix(tarball, ".gz") || strings.HasSuffix(tarball, ".tgz") {
			var err error
			tarball, err = decompressToTemp(tarball, tmpDir)
			if err != nil {
				return nil, err
			}
		}
		ret = append(ret,
			images.Action{Op: &images.TarInCommand{
				TarFile:   tarball,
				RemoteDir: filepath.Dir(policytestsVmTestProgsDir),
			}})
	} else {
		return nil, errors.New("you need to define exactly one of --tester-progs-dir and --tetragon-progs-tarball")
	}

	if !ptConf.JustBoot {
		// tetragon policytester systemd service
		ptArgs := make([]string, 0, len(ptConf.policytestExtraArgs))
		for k, v := range ptConf.policytestExtraArgs {
			ptArgs = append(ptArgs, fmt.Sprintf("--%s=%s", k, v))
		}
		environment := make([]string, 0, len(ptConf.environment))
		for name, value := range ptConf.environment {
			environment = append(environment, strconv.Quote(fmt.Sprintf("%s=%s", name, value)))
		}
		ret = append(ret,
			images.Action{Op: &images.CopyInCommand{
				LocalPath: mustMakeTetragonPolicyTesterServiceFile(filepath.Join(tmpDir, tetragonPolicyTesterService), strings.Join(ptArgs, " "), strings.Join(environment, " ")),
				RemoteDir: "/etc/systemd/system/",
			}},
			images.Action{Op: &images.RunCommand{
				Cmd: "systemctl enable " + tetragonPolicyTesterService,
			}})
	}

	return ret, nil
}

func buildPolicyTestImage(log slogger.Logger, ptConf *PolicyTestConf, tmpDir string) error {
	fsActions, err := lvh.FilesystemActions(ptConf.Filesystems, tmpDir)
	if err != nil {
		return err
	}

	netActions, err := lvh.NetActions(tmpDir)
	if err != nil {
		return err
	}

	tetragonActions, err := buildTetragonActions(ptConf, tmpDir)
	if err != nil {
		return err
	}

	actions := lvh.BaseActions(&ptConf.Conf)
	actions = append(actions, tetragonActions...)
	actions = append(actions, fsActions...)
	actions = append(actions, netActions...)

	return lvh.BuildImage(log, &ptConf.Conf, actions, true)
}

func runPolicyTests(
	cnf *PolicyTestConf, qemuBin string, qemuArgs []string,
) (*policytest.ResultsSummary, error) {
	ctx := context.Background()
	ctx, cancel := signal.NotifyContext(ctx, unix.SIGINT, unix.SIGTERM)
	defer cancel()
	qemuCmd := exec.CommandContext(ctx, qemuBin, qemuArgs...)

	// buffer output from qemu's  stdout/stderr to avoid delays
	bout := bufio.NewWriter(os.Stdout)
	berr := bufio.NewWriter(os.Stderr)
	qemuCmd.Stdout = bout
	qemuCmd.Stderr = berr

	t0 := time.Now()
	if err := qemuCmd.Run(); err != nil {
		return nil, err
	}
	bout.Flush()
	berr.Flush()

	fmt.Printf("results directory: %s (total time:%.2fs)\n", cnf.resultsDir, time.Since(t0).Seconds())
	resFile := filepath.Join(cnf.resultsDir, "results.json")
	f, err := os.Open(resFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open results file %s: %w", resFile, err)
	}
	defer f.Close()
	var summary = policytest.NewResultsSummary()
	var results []*policytest.NamedResult
	for result, err := range policytest.DecodeResults(f, os.Stderr) {
		if err != nil {
			return nil, err
		}
		summary.Update(result.Result)
		results = append(results, result)
	}
	policytest.DumpResults(os.Stdout, results)
	return summary, nil
}
