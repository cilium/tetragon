// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package testutils

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"testing"
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

type LineParser = func(line string) error

func parseAndLog(t *testing.T, rd *bufio.Reader, prefix string, lp LineParser) {
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			if !errors.Is(err, io.EOF) {
				t.Logf("%s: error: %s", prefix, err)
			}
			return
		}
		if lp != nil {
			err = lp(line)
			if err != nil {
				t.Logf("%s: parsing error: %s", prefix, err)
			}
		}
		t.Logf("%s: %s", prefix, line)
	}
}

// startParseAndLog starts a parseAndLog goroutine
func startParseAndLog(
	t *testing.T,
	wg *sync.WaitGroup,
	rd *bufio.Reader,
	logPrefix string,
	lp LineParser,
) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		parseAndLog(t, rd, logPrefix, lp)
	}()
}

// ParseAndLogCmdOutput will log command output using t.Log, and also call the
// lineparser functions for each line. This will happen in two goroutines. It
// returns a waitgroup for them finishing.
func (cbp *CmdBufferedPipes) ParseAndLogCmdOutput(
	t *testing.T,
	parseOut LineParser,
	parseErr LineParser,
) *sync.WaitGroup {
	var wg sync.WaitGroup
	startParseAndLog(t, &wg, cbp.StdoutRd, "stdout>", parseOut)
	startParseAndLog(t, &wg, cbp.StderrRd, "stderr>", parseErr)
	return &wg
}
