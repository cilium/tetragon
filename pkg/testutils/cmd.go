// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package testutils

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"testing"

	"github.com/spf13/cobra"
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

func RunCmdAndLogOutput(t *testing.T, cmd *exec.Cmd) error {
	cbp, err := NewCmdBufferedPipes(cmd)
	if err != nil {
		t.Fatal(err)
	}
	err = cmd.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer cbp.Close()
	wg := cbp.ParseAndLogCmdOutput(t, nil, nil)
	wg.Wait()
	return cmd.Wait()
}

// MockPipedFile mocks the file being piped into stdin, similarly as what you
// can do with `cat file | cmd`. It restores the original os.Stdin in t.Cleanup.
// It's using a goroutine to copy the file content to the writer of the pipe.
func MockPipedFile(t *testing.T, filename string) {
	file, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		_, err := io.Copy(w, file)
		defer file.Close()
		defer w.Close()
		if err != nil {
			// this should not happen but can be useful
			panic(err)
		}
	}()

	oldStdin := os.Stdin
	t.Cleanup(func() {
		// using closure to restore stdin after the test
		os.Stdin = oldStdin
		r.Close()
	})

	os.Stdin = r
}

// RedirectStdoutExecuteCmd redirects stdout, executes the command and returns
// the result of the command.
func RedirectStdoutExecuteCmd(t *testing.T, cmd *cobra.Command) []byte {
	// redirect stdout because most commands are writing directly to it
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w

	done := make(chan error, 1)
	buf := bytes.Buffer{}
	go func(ch chan error) {
		_, err := io.Copy(&buf, r)
		defer r.Close()
		if err != nil {
			ch <- err
		}
		ch <- nil
	}(done)

	cmd.Execute()
	// restore stdout
	os.Stdout = oldStdout
	w.Close()

	err = <-done
	if err != nil {
		t.Fatal(err)
	}

	return buf.Bytes()
}
