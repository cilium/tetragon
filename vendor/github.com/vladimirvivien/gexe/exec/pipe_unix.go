//go:build !windows

package exec

import "errors"

// Pipe executes each command serially chaining the combinedOutput
// of previous command to the input Pipe of next command.
func (cb *CommandBuilder) Pipe() *PipedCommandResult {
	if cb.err != nil {
		return &PipedCommandResult{err: cb.err}
	}

	result := cb.connectProcPipes()

	// check for structural errors
	if result.err != nil {
		return result
	}

	// start each process (but, not wait for result)
	// to ensure data flow between successive processes start
	for _, p := range cb.procs {
		result.procs = append(result.procs, p)
		if err := p.Start().Err(); err != nil {
			result.errProcs = append(result.errProcs, p)
			return result
		}
	}

	// wait and access processes result
	for _, p := range cb.procs {
		if err := p.Wait().Err(); err != nil {
			result.errProcs = append(result.errProcs, p)
			break
		}
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

	// setup standard output/err of last proc in pipe
	result.lastProc.cmd.Stdout = cb.stdout
	if cb.stdout == nil {
		result.lastProc.cmd.Stdout = result.lastProc.result
	}

	// Wire standard error of last proc in pipe
	result.lastProc.cmd.Stderr = cb.stderr
	if cb.stderr == nil {
		result.lastProc.cmd.Stderr = result.lastProc.result
	}

	// setup pipes for inner procs in the pipe chain
	result.lastProc.cmd.Stdout = result.lastProc.result
	for i, p := range cb.procs[:last] {
		pipeout, err := p.cmd.StdoutPipe()
		if err != nil {
			p.err = err
			return &PipedCommandResult{err: err, errProcs: []*Proc{p}}
		}

		cb.procs[i+1].cmd.Stdin = pipeout
	}

	return &result
}
