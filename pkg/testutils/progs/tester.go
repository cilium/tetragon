// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package progs

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"github.com/cilium/tetragon/pkg/testutils"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// Tester provides an interface to using tester from tests
type Tester struct {
	Cmd          *exec.Cmd
	progStdout   io.ReadCloser
	progStdin    io.WriteCloser
	stdoutReader *bufio.Reader
}

// This is what tester (the binary) will execute.
func TestHelperMain() {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		execMayFail := false
		cmd := scanner.Text()
		switch {
		case cmd == "ping":
			fmt.Println("pong")

		case strings.HasPrefix(cmd, "exec_mayfail "):
			execMayFail = true
			fallthrough
		case strings.HasPrefix(cmd, "exec "):
			fields := strings.Fields(cmd)
			if len(fields) < 2 {
				fmt.Fprintf(os.Stderr, "invalid cmd='%s'\n", cmd)
				os.Exit(1)
			}
			cmdName := fields[1]
			cmdArgs := []string{}
			if len(fields) > 2 {
				cmdArgs = append(cmdArgs, fields[2:]...)
			}
			cmd := exec.Command(cmdName, cmdArgs...)
			out, err := cmd.CombinedOutput()
			if err == nil {
				fmt.Fprintf(os.Stdout, "cmd=%q returned without an error. Combined output was: %q\n", cmd, out)
				continue
			}
			if !execMayFail {
				fmt.Fprintf(os.Stderr, "cmd=%q returned an error (%s)\n", cmd, err)
				os.Exit(1)
			}
			fmt.Fprintf(os.Stdout, "cmd=%q returned an error %q\n", cmd, err)

		case strings.HasPrefix(cmd, "lseek "):
			fields := strings.Fields(cmd)
			fd, err := strconv.ParseInt(fields[1], 10, 32)
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid fd: %s", fields[1])
				os.Exit(1)
			}
			off, err := strconv.ParseInt(fields[2], 10, 64)
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid off: %s", fields[2])
				os.Exit(1)
			}
			whence, err := strconv.ParseInt(fields[3], 10, 32)
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid whence: %s", fields[3])
				os.Exit(1)
			}

			o, err := unix.Seek(int(fd), off, int(whence))
			fmt.Fprintf(os.Stdout, "cmd=%q returned o=%d err=%v\n", cmd, o, err)

		case cmd == "getcpu":
			var cpu, node int
			_, _, err := unix.Syscall(
				unix.SYS_GETCPU,
				uintptr(unsafe.Pointer(&cpu)),
				uintptr(unsafe.Pointer(&node)),
				0,
			)
			fmt.Fprintf(os.Stdout, "getpcu returned: err:%v\n", err)

		case cmd == "exit":
			fmt.Fprintf(os.Stderr, "Exiting...\n")
			os.Exit(0)

		default:
			fmt.Fprintf(os.Stdout, "unknown cmd=%s\n", cmd)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing stdin: %v", err)
		os.Exit(1)
	}
}

//revive:disable:context-as-argument
func StartTester(t *testing.T, ctx context.Context) *Tester {

	prog := testutils.RepoRootPath("contrib/tester-progs/test-helper")
	cmd := exec.CommandContext(ctx, prog)

	progStderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("stderr pipe filed: %v", err)
	}
	t.Cleanup(func() { progStderr.Close() })

	progStdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe filed: %v", err)
	}
	t.Cleanup(func() { progStdout.Close() })

	progStdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe filed: %v", err)
	}
	t.Cleanup(func() { progStdin.Close() })

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start syscall-tester: %v", err)
	}

	// print stderr in the logs
	go func() {
		scanner := bufio.NewScanner(progStderr)
		for scanner.Scan() {
			t.Logf("tester stderr> %s", scanner.Text())
		}
	}()

	return &Tester{
		Cmd:          cmd,
		progStdout:   progStdout,
		progStdin:    progStdin,
		stdoutReader: bufio.NewReader(progStdout),
	}
}

func (pt *Tester) Command(s string) (string, error) {
	_, err := fmt.Fprintln(pt.progStdin, s)
	if err != nil {
		return "", fmt.Errorf("failed to write command to stdin: %w", err)
	}

	// NB: We assume that the tester (see TesterMain) always returns a single line of output in
	// stdout
	s, err = pt.stdoutReader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read output: %w", err)
	}

	return strings.TrimSpace(s), nil
}

func (pt *Tester) Ping() error {
	out, err := pt.Command("ping")
	if err != nil {
		return fmt.Errorf("ping failed: %w", err)
	}
	if out != "pong" {
		return fmt.Errorf("unexpected output from stdout: %s", out)
	}
	return nil
}

// Exec is very basic. tester will split arguments using strings.Fields() (see TesterMain), execute the comand, and
// return its combined output in stdout.
func (pt *Tester) Exec(cmd string) (string, error) {
	execCmd := fmt.Sprintf("exec %s", cmd)
	out, err := pt.Command(execCmd)
	if err != nil {
		return "", fmt.Errorf("exec failed: %w", err)
	}
	return out, nil
}

// similar to Exec, but command may fail
func (pt *Tester) ExecMayFail(cmd string) (string, error) {
	execCmd := fmt.Sprintf("exec_mayfail %s", cmd)
	out, err := pt.Command(execCmd)
	if err != nil {
		return "", fmt.Errorf("exec_mayfail failed: %w", err)
	}
	return out, nil
}

func (pt *Tester) Lseek(fd, off, whence int) (string, error) {
	lseekCmd := fmt.Sprintf("lseek %d %d %d", fd, off, whence)
	out, err := pt.Command(lseekCmd)
	if err != nil {
		return "", fmt.Errorf("exec failed: %w", err)
	}
	return out, nil
}

func (pt *Tester) Stop() error {
	_, err := fmt.Fprintln(pt.progStdin, "exit")
	if err != nil {
		return err
	}
	return pt.Cmd.Wait()
}

func (pt *Tester) AddToCgroup(t *testing.T, cgroupPath string) {
	pid := pt.Cmd.Process.Pid
	procs := filepath.Join(cgroupPath, "cgroup.procs")
	pidStr := fmt.Sprintf("%d", pid)
	err := os.WriteFile(procs, []byte(pidStr), 0644)
	require.NoError(t, err, fmt.Sprintf("failed to add pid '%s' to %s", pidStr, procs))
	// TODO: add check that cgroup is what we set
}
