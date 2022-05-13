// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package testutils

import (
	"bufio"
	"fmt"
	"io"
	"os/exec"
)

// CmdPipes maintains pipes for stdout, stderr, and stdin
type CmdPipes struct {
	Stdout, Stderr io.ReadCloser
	Stdin          io.WriteCloser
}

// NewCmdPipes returns a new CmdPipes
func NewCmdPipes(cmd *exec.Cmd) (*CmdPipes, error) {
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("StdErrPipe failed: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stderr.Close()
		return nil, fmt.Errorf("StdOutPipe failed: %w", err)
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		stderr.Close()
		stdout.Close()
		return nil, fmt.Errorf("StdinPipe() failed: %w", err)
	}

	return &CmdPipes{
		Stdout: stdout,
		Stderr: stderr,
		Stdin:  stdin,
	}, nil
}

// Close closes all the pipes
func (cp *CmdPipes) Close() {
	cp.Stdout.Close()
	cp.Stderr.Close()
	cp.Stdin.Close()
}

// CmdBufferedPipes wraps stdout and stderr in a bufio.Reader
type CmdBufferedPipes struct {
	P                  *CmdPipes
	StdoutRd, StderrRd *bufio.Reader
}

func (cbp *CmdBufferedPipes) Close() {
	cbp.P.Close()
}

func NewCmdBufferedPipes(cmd *exec.Cmd) (*CmdBufferedPipes, error) {
	pipes, err := NewCmdPipes(cmd)
	if err != nil {
		return nil, err
	}

	return &CmdBufferedPipes{
		P:        pipes,
		StdoutRd: bufio.NewReader(pipes.Stdout),
		StderrRd: bufio.NewReader(pipes.Stderr),
	}, nil
}
