// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"syscall"
)

// CmdTrigger simply wraps a exec.CommandContext().Run() into a Trigger
type CmdTrigger struct {
	Bin  string
	Args []string
}

func NewCmdTrigger(bin string, args ...string) *CmdTrigger {
	return &CmdTrigger{
		Bin:  bin,
		Args: args,
	}
}

func (c *CmdTrigger) Trigger(ctx context.Context) error {
	return exec.CommandContext(ctx, c.Bin, c.Args...).Run()
}

func (c *CmdTrigger) ExpectExitCode(val int) *ExecTester {
	return &ExecTester{
		triggers:         []CmdTrigger{*c},
		ExpectedExitCode: []int{val},
	}
}

func (c *CmdTrigger) ExpectSignal(sig syscall.Signal) *ExecTester {
	return &ExecTester{
		triggers:       []CmdTrigger{*c},
		ExpectedSignal: []syscall.Signal{sig},
	}
}

// MultiCmdTrigger simply wraps multiple exec.CommandContext().Run() into a Trigger
type MultiCmdTrigger struct {
	triggers []CmdTrigger
}

func NewMultiCmdTrigger(triggers []CmdTrigger) *MultiCmdTrigger {
	return &MultiCmdTrigger{
		triggers: triggers,
	}
}

func (c *MultiCmdTrigger) Trigger(ctx context.Context) error {
	for _, trigger := range c.triggers {
		if err := exec.CommandContext(ctx, trigger.Bin, trigger.Args...).Run(); err != nil {
			return err
		}
	}
	return nil
}

func (c *MultiCmdTrigger) ExpectExitCodes(vals []int) *ExecTester {
	return &ExecTester{
		MultiCmdTrigger:  *c,
		ExpectedExitCode: vals,
	}
}

func (c *MultiCmdTrigger) ExpectSignals(sigs []syscall.Signal) *ExecTester {
	return &ExecTester{
		MultiCmdTrigger: *c,
		ExpectedSignal:  sigs,
	}
}

type ExecTester struct {
	MultiCmdTrigger
	// Execution should either terminate normally (with an exit code) or by a signal
	// only one of those should be not nill
	ExpectedExitCode []int
	ExpectedSignal   []syscall.Signal
}

func (et *ExecTester) Trigger(ctx context.Context) error {
	for idx, trigger := range et.triggers {
		cmd := exec.CommandContext(ctx, trigger.Bin, trigger.Args...)
		err := cmd.Start()
		if err != nil {
			return fmt.Errorf("failed to execute cmd: %w", err)
		}
		cmd.Wait()
		err = et.check(cmd, idx)
		if err != nil {
			return err
		}
	}
	return nil
}

// ExecTestError will be returned if the command did not exit as expected.
// That is, either via the expected signal or with the expected error code
type ExecTestError struct {
	s string
}

func NewExecTestErr(format string, args ...any) *ExecTestError {
	return &ExecTestError{fmt.Sprintf(format, args...)}
}

func (e *ExecTestError) Error() string {
	return e.s
}

// check should be called after command has been executed
func (et *ExecTester) check(cmd *exec.Cmd, idx int) error {
	st := cmd.ProcessState.Sys()
	status, ok := st.(syscall.WaitStatus)
	if !ok {
		return fmt.Errorf("BUG: unexpected status type (%T)", st)
	}

	if status.Exited() {
		return et.checkExit(cmd, status.ExitStatus(), idx)
	}

	if status.Signaled() {
		return et.checkSignal(cmd, status.Signal(), idx)
	}

	// if neither status.Exited() or status.Signaled() is true, the process was stopped
	return errors.New("process stopped")
}

func (et *ExecTester) checkSignal(cmd *exec.Cmd, exitSignal syscall.Signal, idx int) error {
	if len(et.ExpectedExitCode) > idx {
		expected := et.ExpectedExitCode[idx]
		return NewExecTestErr("command %v terminated by a signal (%d), but was expected to exit normally with %d", cmd, exitSignal, expected)
	}
	if len(et.ExpectedSignal) <= idx {
		return errors.New("BUG: neither ExpectExitCode or ExpectSignal defined")
	}
	expected := et.ExpectedSignal[idx]
	if expected != exitSignal {
		return NewExecTestErr("command %v terminated by signal %d, but was expected to terminate with signal %d", cmd, exitSignal, expected)
	}

	return nil
}

// checkExit checks exit expectations when the process exited normally (i.e., without a signal)
func (et *ExecTester) checkExit(cmd *exec.Cmd, exitStatus int, idx int) error {
	if len(et.ExpectedSignal) > idx {
		expected := et.ExpectedSignal[idx]
		return NewExecTestErr("command %v terminated normally (%d), but was expected to exit via a signal (%d)", cmd, exitStatus, expected)
	}
	if len(et.ExpectedExitCode) <= idx {
		return errors.New("BUG: neither ExpectExitCode or ExpectSignal defined")
	}

	expected := et.ExpectedExitCode[idx]
	if expected != exitStatus {
		return NewExecTestErr("command %v terminated normally with %d, but was expected to terminate with %d", cmd, exitStatus, expected)
	}

	return nil
}
