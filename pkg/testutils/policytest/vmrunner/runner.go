// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

// Package vmrunner runs the policy tests in a little-vm-helper VM.
package vmrunner

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/cilium/little-vm-helper/pkg/slogger"

	"github.com/cilium/tetragon/pkg/testutils/policytest"
	"github.com/cilium/tetragon/pkg/vmtests/lvh"
)

const (
	// results from the VM land in this directory, shared with the host
	resultsVMDir = "/policytests-results"
	// the unit writes how the tetra in the VM ended to this file in there
	statusFile = "status"
)

var (
	errTetragonSource = errors.New("define exactly one of TetragonInstallDir and TetragonTarball")
	errTesterProgsSrc = errors.New("define exactly one of TesterProgsDir and TesterProgsTarball")
	errUnitArgLine    = errors.New("an argument for the unit contains a line break")
	errVMNoStatus     = errors.New("the VM left no status, so the tests never started")
	errVMBadStatus    = errors.New("the VM left a status it should not have")
	errVMFailed       = errors.New("the tetra in the VM did not finish")

	// unitEscaper escapes an argument inside double quotes on a systemd
	// ExecStart line: backslash escapes, and doubled % and $ so that systemd
	// expands neither specifiers nor variables
	unitEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "%", "%%", "$", "$$")
)

// Conf configures VMRunner.
type Conf struct {
	lvh.Conf
	// TetragonInstallDir or TetragonTarball provides tetragon and tetra
	TetragonInstallDir string
	TetragonTarball    string
	// TesterProgsDir or TesterProgsTarball provides the tester programs
	TesterProgsDir     string
	TesterProgsTarball string
	// ResultsDir on the host receives results.json; empty makes a temp dir
	ResultsDir string
	// ExtraArgs are passed to the tetra in the VM ahead of the selection
	ExtraArgs []string
	// Environment of the tetra in the VM
	Environment map[string]string
	// Logs receives the lines of the results file that are not results; nil
	// drops them
	Logs io.Writer
	// Console receives the VM console and the qemu output; nil drops them
	Console io.Writer
}

// policytestArgs renders the arguments of the tetra policytest run in the VM
// for its unit's ExecStart line.
func (c *Conf) policytestArgs(sel *policytest.Selection) (string, error) {
	args := append(slices.Clone(c.ExtraArgs), sel.Args()...)
	for i, arg := range args {
		quoted, err := unitArg(arg)
		if err != nil {
			return "", err
		}
		args[i] = quoted
	}
	return strings.Join(args, " "), nil
}

// unitArg quotes an argument for a systemd ExecStart line.
func unitArg(arg string) (string, error) {
	if strings.ContainsAny(arg, "\n\r") {
		return "", fmt.Errorf("%w: %q", errUnitArgLine, arg)
	}
	return `"` + unitEscaper.Replace(arg) + `"`, nil
}

// VMRunner runs the tests in a VM. It builds an image with tetragon, the
// tester programs and a oneshot unit that runs `tetra policytest run
// --output json` into a directory shared with the host, boots it, and once
// the unit has powered the VM off, reads the results back and yields them
// all at that point. Building the image changes the working directory of the
// process while little-vm-helper runs, so use one VMRunner at a time.
type VMRunner struct {
	conf     *Conf
	log      slogger.Logger
	tmpDir   string
	qemuBin  string
	qemuArgs []string
	// ownResultsDir is set when NewVMRunner made the results directory
	ownResultsDir bool
}

// NewVMRunner prepares the VM: the results directory shared with it, the
// base image, and the qemu command. It works on a copy of conf.
func NewVMRunner(ctx context.Context, log *slog.Logger, conf *Conf) (*VMRunner, error) {
	if (conf.TetragonInstallDir == "") == (conf.TetragonTarball == "") {
		return nil, errTetragonSource
	}
	if (conf.TesterProgsDir == "") == (conf.TesterProgsTarball == "") {
		return nil, errTesterProgsSrc
	}

	tmpDir, err := os.MkdirTemp("", "tetragon-policytests-")
	if err != nil {
		return nil, fmt.Errorf("failed to make temp dir: %w", err)
	}
	c := *conf
	c.Filesystems = slices.Clone(c.Filesystems)
	vm := &VMRunner{conf: &c, log: slogger.NewWithHandler(log.Handler()), tmpDir: tmpDir}

	if c.ResultsDir == "" {
		c.ResultsDir, err = os.MkdirTemp("", "policytests-results-")
		if err != nil {
			vm.Close()
			return nil, fmt.Errorf("failed to make results dir: %w", err)
		}
		vm.ownResultsDir = true
	}
	c.Filesystems = append(c.Filesystems, &lvh.VirtIOFS{
		ID:      "results",
		HostDir: c.ResultsDir,
		VMDir:   resultsVMDir,
	})

	if err := c.MaybePullBaseImage(ctx, tmpDir); err != nil {
		vm.Close()
		return nil, err
	}
	vm.qemuBin, vm.qemuArgs, err = lvh.QemuCommand(vm.log, c.Conf)
	if err != nil {
		vm.Close()
		return nil, err
	}
	return vm, nil
}

// Build builds the VM image. With a selection, the VM runs it at boot and
// powers off; without one, it just boots.
func (vm *VMRunner) Build(sel *policytest.Selection) error {
	// every build stages its files afresh
	buildDir, err := os.MkdirTemp(vm.tmpDir, "build-")
	if err != nil {
		return fmt.Errorf("failed to make build dir: %w", err)
	}
	return buildImage(vm.log, vm.conf, buildDir, sel)
}

// Qemu returns the qemu binary and arguments that boot the image.
func (vm *VMRunner) Qemu() (string, []string) {
	return vm.qemuBin, vm.qemuArgs
}

// Close removes the temporary files. A results directory that NewVMRunner
// made stays when it holds results and goes when it is empty.
func (vm *VMRunner) Close() error {
	if vm.ownResultsDir {
		// fails on a non-empty directory, which is the point
		os.Remove(vm.conf.ResultsDir)
	}
	return os.RemoveAll(vm.tmpDir)
}

// Run runs the selection in the VM and yields the results once it has
// powered off.
func (vm *VMRunner) Run(ctx context.Context, log *slog.Logger, sel *policytest.Selection) iter.Seq2[*policytest.NamedResult, error] {
	return func(yield func(*policytest.NamedResult, error) bool) {
		if err := vm.run(ctx, log, sel); err != nil {
			yield(nil, err)
			return
		}

		status, err := os.ReadFile(filepath.Join(vm.conf.ResultsDir, statusFile))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				err = errVMNoStatus
			}
			yield(nil, err)
			return
		}

		summary := policytest.NewResultsSummary()
		resFile := filepath.Join(vm.conf.ResultsDir, "results.json")
		f, err := os.Open(resFile)
		switch {
		case errors.Is(err, os.ErrNotExist):
			// nothing to decode; the status tells why
		case err != nil:
			yield(nil, fmt.Errorf("failed to open results file %s: %w", resFile, err))
			return
		default:
			defer f.Close()
			for res, err := range policytest.DecodeResults(f, vm.conf.Logs) {
				if err != nil {
					yield(nil, err)
					return
				}
				summary.Update(res.Result)
				if !yield(res, nil) {
					return
				}
			}
		}

		if err := vmError(strings.TrimSpace(string(status)), summary); err != nil {
			yield(nil, err)
		}
	}
}

// vmError turns the status the unit left, "$SERVICE_RESULT $EXIT_CODE
// $EXIT_STATUS", into an error: a tetra that ended for any reason other than
// a clean exit, except exit 1 with failed results, which the results already
// say.
func vmError(status string, summary *policytest.ResultsSummary) error {
	fields := strings.Fields(status)
	if len(fields) != 3 {
		return fmt.Errorf("%w: %q", errVMBadStatus, status)
	}
	switch {
	case fields[0] == "success":
		if summary.Total == 0 {
			return fmt.Errorf("%w: the VM powered off without any", policytest.ErrNoResults)
		}
		return nil
	case fields[0] == "exit-code" && fields[2] == "1" && summary.Errs > 0:
		return nil
	}
	return fmt.Errorf("%w: %s", errVMFailed, status)
}

// run builds the image for the selection and boots the VM until the unit
// powers it off.
func (vm *VMRunner) run(ctx context.Context, log *slog.Logger, sel *policytest.Selection) error {
	if err := sel.Validate(); err != nil {
		return err
	}
	if err := vm.Build(sel); err != nil {
		return err
	}
	// what an earlier run left in the same directory must not pass as new
	for _, name := range []string{"results.json", statusFile} {
		if err := os.Remove(filepath.Join(vm.conf.ResultsDir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("failed to remove the old %s: %w", name, err)
		}
	}

	qemuCmd := exec.CommandContext(ctx, vm.qemuBin, vm.qemuArgs...)

	// buffer the console output to avoid delays
	console := vm.conf.Console
	if console == nil {
		console = io.Discard
	}
	out := bufio.NewWriter(console)
	qemuCmd.Stdout = out
	qemuCmd.Stderr = out

	t0 := time.Now()
	err := qemuCmd.Run()
	out.Flush()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return fmt.Errorf("qemu failed: %w", err)
	}

	log.Info("VM finished", "results", vm.conf.ResultsDir, "duration", time.Since(t0).Round(10*time.Millisecond))
	return nil
}
