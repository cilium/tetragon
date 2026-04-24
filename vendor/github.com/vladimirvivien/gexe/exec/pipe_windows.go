//go:build windows

package exec

import (
	"bytes"
	"errors"
	"strings"
)

// Pipe executes each Windows command serially. Windows, however, does not support
// OS pipes like {Li|U}nix. Instead, pipes use a single command string, with | delimiters,
// passed to powershell. So prior to calling Pipe(), call CommandBulider.WithShell()
// to specify "powershell.exe -c" as the shell.
// (See tests for examples.)
func (cb *CommandBuilder) Pipe() *PipedCommandResult {
	if cb.err != nil {
		return &PipedCommandResult{err: cb.err}
	}

	result := new(PipedCommandResult)

	// setup a single command string with pipe delimiters
	cmd := strings.Join(cb.cmdStrings, " | ")

	// Prepend shell command if specified
	if cb.shellStr != "" {
		cmd = cb.shellStr + " " + cmd
	}

	proc := NewProcWithVars(cmd, cb.vars)
	result.procs = append(result.procs, proc)
	result.lastProc = proc

	// execute the piped commands
	if err := cb.runCommand(proc); err != nil {
		return &PipedCommandResult{err: err, errProcs: []*Proc{proc}}
	}

	return result
}

// connectProcPipes connects the output of each process to the input of the next process in the chain.
// It returns a PipedCommandResult containing the connected processes and any errors encountered.
func (cb *CommandBuilder) connectProcPipes() *PipedCommandResult {
	var result PipedCommandResult

	procLen := len(cb.procs)
	if procLen == 0 {
		return &PipedCommandResult{err: errors.New("no processes to connect")}
	}

	// wire last proc to combined output
	last := procLen - 1
	result.lastProc = cb.procs[last]

	// setup standard output/err for last proc in pipe
	result.lastProc.cmd.Stdout = cb.stdout
	if cb.stdout == nil {
		result.lastProc.cmd.Stdout = result.lastProc.result
	}

	// Wire the remainder procs
	result.lastProc.cmd.Stderr = cb.stderr
	if cb.stderr == nil {
		result.lastProc.cmd.Stderr = result.lastProc.result
	}

	// exec.Command.StdoutPipe() uses OS pipes, which are not supported on Windows.
	// Instead, this uses an in-memory pipe and set the command's stdin to the write end of the pipe.
	result.lastProc.cmd.Stdout = result.lastProc.result
	for i := range cb.procs[:last] {
		// Create an in-memory pipe for the command's stdout
		pipe := new(bytes.Buffer)
		cb.procs[i].cmd.Stdout = pipe
		cb.procs[i+1].cmd.Stdin = pipe
	}

	return &result
}
