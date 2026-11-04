// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

// Package vmrunner runs the policy tests in a little-vm-helper VM.
package vmrunner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/little-vm-helper/pkg/slogger"

	"github.com/cilium/tetragon/pkg/testutils/policytest"
	"github.com/cilium/tetragon/pkg/vmtests/lvh"
)

const (
	resultsVMDir = "/policytests-results"
	statusFile   = "status"
)

var (
	errTetragonSource = errors.New("define exactly one of TetragonInstallDir and TetragonTarball")
	errTesterProgsSrc = errors.New("define exactly one of TesterProgsDir and TesterProgsTarball")
	errUnitArgLine    = errors.New("an argument for the unit contains a line break")
	errVMNoStatus     = errors.New("the VM left no status, so the tests never started")
	errVMBadStatus    = errors.New("the VM left a status it should not have")
	errVMFailed       = errors.New("the tetra in the VM did not finish")

	// unitEscaper doubles % and $ so that systemd expands neither specifiers
	// nor variables
	unitEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "%", "%%", "$", "$$")
)

// Conf configures Runner.
type Conf struct {
	lvh.Conf
	// TetragonInstallDir or TetragonTarball provides tetragon and tetra
	TetragonInstallDir string
	TetragonTarball    string
	// TesterProgsDir or TesterProgsTarball provides the tester programs
	TesterProgsDir     string
	TesterProgsTarball string
	// ExtraArgs are passed to the tetra in the VM ahead of the selection
	ExtraArgs   []string
	Environment map[string]string
	// Console receives the VM console and the qemu output; nil drops them
	Console io.Writer
}

func (c *Conf) policytestArgs(sel *policytest.Selection) (string, error) {
	selArgs, err := sel.Args()
	if err != nil {
		return "", err
	}
	args := append(slices.Clone(c.ExtraArgs), selArgs...)
	for i, arg := range args {
		quoted, err := unitArg(arg)
		if err != nil {
			return "", err
		}
		args[i] = quoted
	}
	return strings.Join(args, " "), nil
}

func unitArg(arg string) (string, error) {
	if strings.ContainsAny(arg, "\n\r") {
		return "", fmt.Errorf("%w: %q", errUnitArgLine, arg)
	}
	return `"` + unitEscaper.Replace(arg) + `"`, nil
}

// Runner runs the tests in a VM. Building the image changes the working
// directory of the process while little-vm-helper runs, so use one Runner at
// a time.
type Runner struct {
	conf       *Conf
	log        slogger.Logger
	tmpDir     string
	qemuBin    string
	qemuArgs   []string
	resultsDir string
}

// New prepares the VM. It works on a copy of conf.
func New(ctx context.Context, log *slog.Logger, conf *Conf) (*Runner, error) {
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
	vm := &Runner{conf: &c, log: slogger.NewWithHandler(log.Handler()), tmpDir: tmpDir}

	vm.resultsDir, err = os.MkdirTemp("", "policytests-results-")
	if err != nil {
		vm.Close()
		return nil, fmt.Errorf("failed to make results dir: %w", err)
	}
	c.Filesystems = append(c.Filesystems, &lvh.VirtIOFS{
		ID:      "results",
		HostDir: vm.resultsDir,
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
func (vm *Runner) Build(sel *policytest.Selection) error {
	// every build stages its files afresh
	buildDir, err := os.MkdirTemp(vm.tmpDir, "build-")
	if err != nil {
		return fmt.Errorf("failed to make build dir: %w", err)
	}
	return buildImage(vm.log, vm.conf, buildDir, sel)
}

// Qemu returns the qemu binary and arguments that boot the image.
func (vm *Runner) Qemu() (string, []string) {
	return vm.qemuBin, vm.qemuArgs
}

// Close removes the temporary files. The results directory stays when it
// holds results and goes when it is empty.
func (vm *Runner) Close() error {
	os.Remove(vm.resultsDir)
	return os.RemoveAll(vm.tmpDir)
}

// Run builds the image for the selection, boots the VM and yields the
// results once it has powered off.
func (vm *Runner) Run(ctx context.Context, log *slog.Logger, sel *policytest.Selection) iter.Seq2[*policytest.NamedResult, error] {
	return func(yield func(*policytest.NamedResult, error) bool) {
		if err := vm.run(ctx, log, sel); err != nil {
			yield(nil, err)
			return
		}

		status, err := os.ReadFile(filepath.Join(vm.resultsDir, statusFile))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				err = errVMNoStatus
			}
			yield(nil, err)
			return
		}

		summary := policytest.NewResultsSummary()
		resFile := filepath.Join(vm.resultsDir, "results.json")
		f, err := os.Open(resFile)
		switch {
		case errors.Is(err, os.ErrNotExist):
			// nothing to decode; the status tells why
		case err != nil:
			yield(nil, fmt.Errorf("failed to open results file %s: %w", resFile, err))
			return
		default:
			defer f.Close()
			for res, err := range policytest.DecodeResults(f, nil) {
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

// vmError maps the status the unit left, "$SERVICE_RESULT $EXIT_CODE
// $EXIT_STATUS", to EndError.
func vmError(status string, summary *policytest.ResultsSummary) error {
	fields := strings.Fields(status)
	if len(fields) != 3 {
		return fmt.Errorf("%w: %q", errVMBadStatus, status)
	}
	exitCode := -1
	switch fields[0] {
	case "success":
		exitCode = 0
	case "exit-code":
		if code, err := strconv.Atoi(fields[2]); err == nil {
			exitCode = code
		}
	}
	return summary.EndError(exitCode, fmt.Errorf("%w: %s", errVMFailed, status))
}

func (vm *Runner) run(ctx context.Context, log *slog.Logger, sel *policytest.Selection) error {
	if err := vm.Build(sel); err != nil {
		return err
	}
	// what an earlier run left in the same directory must not pass as new
	for _, name := range []string{"results.json", statusFile} {
		if err := os.Remove(filepath.Join(vm.resultsDir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("failed to remove the old %s: %w", name, err)
		}
	}

	console := vm.conf.Console
	if console == nil {
		console = io.Discard
	}
	t0 := time.Now()
	if err := lvh.RunQemu(ctx, vm.qemuBin, vm.qemuArgs, console, console); err != nil {
		return err
	}

	log.Info("VM finished", "results", vm.resultsDir, "duration", time.Since(t0).Round(10*time.Millisecond))
	return nil
}
