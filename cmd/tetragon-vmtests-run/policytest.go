// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/cilium/little-vm-helper/pkg/arch"
	"github.com/cilium/little-vm-helper/pkg/images"
	"github.com/cilium/little-vm-helper/pkg/runner"
	"github.com/cilium/little-vm-helper/pkg/slogger"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"

	"github.com/cilium/tetragon/pkg/testutils/policytest"
)

var (
	policytestsVmResultsDir = "/policytests-results"
)

type PolicyTestConf struct {
	testConf
	tetragonInstallDir string
	tetragonTarball    string
	testerProgsDir     string
	resultsDir         string
}

func (rc PolicyTestConf) testImageFilename() string {
	if ext := filepath.Ext(rc.vmName); ext == "" {
		return rc.vmName + ".qcow2"
	}
	return rc.vmName
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
				cnf.filesystems = append(cnf.filesystems,
					&virtIOFilesystem{
						id:      "host",
						hostdir: mountHostPath,
						vmdir:   "/host",
					},
				)
			}

			if !cnf.justBuildImage && !cnf.dontRebuildImage {
				cnf.resultsDir, err = os.MkdirTemp("", "policytests-results-")
				if err != nil {
					return fmt.Errorf("failed to make results dir: %w", err)
				}
				cnf.filesystems = append(cnf.filesystems,
					&virtIOFilesystem{
						id:      "results",
						hostdir: cnf.resultsDir,
						vmdir:   policytestsVmResultsDir,
					},
				)
			}

			err = buildPolicyTestImage(log, &cnf)
			if err != nil || cnf.justBuildImage {
				return err
			}

			runtimeArch, err := arch.NewArch(runtime.GOARCH)
			if err != nil {
				return fmt.Errorf("failed to create lvh arch: %w", err)
			}

			qemuBin := runtimeArch.QemuBinary()
			qemuArgs, err := buildQemuArgs(log, cnf.testConf)
			if err != nil {
				return fmt.Errorf("failed to build qemu args: %w", err)
			}

			if cnf.qemuPrint {
				qemuPrintCmd(qemuBin, qemuArgs)
				return nil
			}

			// if we don't need to run tests, just exec() so that user will be able to
			// login to the VM.
			if cnf.justBoot {
				return qemuJustBoot(qemuBin, qemuArgs)
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

	cmdAddTestConfFlags(cmd, &cnf.testConf)
	cmd.Flags().StringVar(&cnf.tetragonInstallDir, "tetragon-dir", "", "tetragon install directory")
	cmd.Flags().StringVar(&cnf.tetragonTarball, "tetragon-tarball", "", "tetragon install tarball")
	cmd.Flags().StringVar(&cnf.testerProgsDir, "tester-progs-dir", "", "tetragon tester progs")
	cmd.MarkFlagRequired("tester-progs-dir")
	cmd.Flags().StringArrayVarP(&ports, "port", "p", nil, "Forward a port (hostport[:vmport[:tcp|udp]])")
	cmd.Flags().StringVar(&mountHostPath, "mount-host-path", "", "host path to mount inside VM")
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

	if ptConf.tetragonInstallDir != "" && ptConf.tetragonTarball != "" {
		return nil, errors.New("you need to define exactly one of --tetragon-install-dir and --tetragon-tarball")
	} else if ptConf.tetragonInstallDir != "" {
		ret = append(ret,
			// install.sh
			images.Action{Op: &images.CopyInCommand{
				LocalPath: filepath.Join(ptConf.tetragonInstallDir, "usr", "local"),
				RemoteDir: "/usr",
			}},
			// tetragon systemd service
			images.Action{Op: &images.CopyInCommand{
				LocalPath: mustMakeTetragonServiceFile(filepath.Join(tmpDir, tetragonService)),
				RemoteDir: "/etc/systemd/system/",
			}},
			images.Action{Op: &images.RunCommand{Cmd: "systemctl enable " + tetragonService}},
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
		)
	} else {
		return nil, errors.New("you need to define exactly one of --tetragon-install-dir and --tetragon-tarball")
	}

	// install tester progs
	ret = append(ret, mustCopyTesterProgsCmd(ptConf.testerProgsDir, tmpDir))

	if !ptConf.justBoot {
		// tetragon policytester systemd service
		ret = append(ret,
			images.Action{Op: &images.CopyInCommand{
				LocalPath: mustMakeTetragonPolicyTesterServiceFile(filepath.Join(tmpDir, tetragonPolicyTesterService)),
				RemoteDir: "/etc/systemd/system/",
			}},
			images.Action{Op: &images.RunCommand{
				Cmd: "systemctl enable " + tetragonPolicyTesterService,
			}})
	}

	return ret, nil
}

func buildPolicyTestImage(log slogger.Logger, ptConf *PolicyTestConf) error {
	imagesDir, baseImage := filepath.Split(ptConf.baseImageFilename)
	tmpDir, err := os.MkdirTemp("", "tetragon-policytests-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	fsActions, err := buildFilesystemActions(ptConf.filesystems, tmpDir)
	if err != nil {
		return err
	}

	netActions, err := buildNetActions(tmpDir)
	if err != nil {
		return err
	}

	tetragonActions, err := buildTetragonActions(ptConf, tmpDir)
	if err != nil {
		return err
	}

	actions := []images.Action{
		{Op: &NoNetworkCommand{}},
		{Op: &images.SetHostnameCommand{Hostname: ptConf.vmName}},
		{Op: &images.AppendLineCommand{
			File: "/etc/sysctl.d/local.conf",
			Line: "kernel.panic_on_rcu_stall=1",
		}},
	}

	actions = append(actions, tetragonActions...)
	actions = append(actions, fsActions...)
	actions = append(actions, netActions...)

	cnf := images.ImagesConf{
		Dir: imagesDir,
		// TODO: might be useful to modify the images builder so that
		// we can build this image using qemu-img -b
		Images: []images.ImgConf{{
			Name:    ptConf.testImageFilename(),
			Parent:  baseImage,
			Actions: actions,
		}},
	}

	forest, err := images.NewImageForest(&cnf, false)
	if err != nil {
		log.Fatal(err)
	}

	res := forest.BuildAllImages(&images.BuildConf{
		Log:          log,
		DryRun:       false,
		ForceRebuild: true,
		MergeSteps:   true,
	})

	return res.Err()
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
	decoder := json.NewDecoder(f)
	for {
		var result policytest.NamedResult
		if err := decoder.Decode(&result); err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("JSON decoding failed: %w", err)
		}

		summary.Update(result.Result)
		results = append(results, &result)
	}
	policytest.DumpResults(os.Stdout, results)
	return summary, nil
}
