package exec

import (
	"bytes"
	"fmt"
	"io"
	"os"
	osexec "os/exec"
	"strings"
	"time"
)

// Proc stores process info when running a process
type Proc struct {
	id         int
	err        error
	state      *os.ProcessState
	result     *bytes.Buffer
	outputPipe io.ReadCloser
	errorPipe  io.ReadCloser
	inputPipe  io.WriteCloser
	cmd        *osexec.Cmd
	process    *os.Process
}

// NewProc sets up command string to be started as an OS process, however
// does not start the process.
func NewProc(cmdStr string) *Proc {
	words, err := parse(cmdStr)
	if err != nil {
		return &Proc{err: err}
	}

	command := osexec.Command(words[0], words[1:]...)
	pipeout, outerr := command.StdoutPipe()
	pipeerr, errerr := command.StderrPipe()
	//output := io.MultiReader(pipeout, pipeerr)

	if outerr != nil || errerr != nil {
		return &Proc{err: fmt.Errorf("combinedOutput pipe: %s; %s", outerr, errerr)}
	}

	pipein, inerr := command.StdinPipe()
	if inerr != nil {
		return &Proc{err: fmt.Errorf("inputPipe err: %w", inerr)}
	}

	return &Proc{
		cmd:        command,
		outputPipe: pipeout,
		errorPipe:  pipeerr,
		inputPipe:  pipein,
		result:     new(bytes.Buffer),
	}
}

// StartProc starts an OS process (setup a combined output of stdout, stderr) and does not wait for
// it to complete. You must follow this with either proc.Wait() to wait for result directly. Otherwise,
// call proc.Out() or proc.Result() which automatically waits and gather result.
func StartProc(cmdStr string) *Proc {
	proc := NewProc(cmdStr)
	if proc.Err() != nil {
		return proc
	}
	proc.cmd.Stdout = proc.result
	proc.cmd.Stderr = proc.result
	return proc.Start()
}

// RunProc starts a new process and waits for its completion. Use Proc.Out() or Proc.Result()
// to access the combined result from stdout and stderr.
func RunProc(cmdStr string) *Proc {
	proc := StartProc(cmdStr)
	if proc.Err() != nil {
		return proc
	}
	proc.Out()
	return proc
}

// Run creates and runs a process and waits for its result (combined stdin,stderr) returned as a string value.
// This is equivalent to calling Proc.RunProc() followed by Proc.Result().
func Run(cmdStr string) (result string) {
	return RunProc(cmdStr).Result()
}

// Start starts the associated command as an OS process and does not wait for its result.
// Ensure proper access to the process' input/output (stdin,stdout,stderr) has been
// setup prior to calling p.Start().
// Use p.Err() to access any error that may have occured during execution.
func (p *Proc) Start() *Proc {
	if p.hasStarted() {
		return p
	}

	if p.cmd == nil {
		p.err = fmt.Errorf("cmd is nill")
		return p
	}

	if err := p.cmd.Start(); err != nil {
		p.err = err
		return p
	}

	p.process = p.cmd.Process
	p.id = p.cmd.Process.Pid
	p.state = p.cmd.ProcessState

	return p
}

// Command returns the os/exec.Cmd that started the process
func (p *Proc) Command() *osexec.Cmd {
	return p.cmd
}

// Peek attempts to read process state information
func (p *Proc) Peek() *Proc {
	p.state = p.cmd.ProcessState
	return p
}

// Wait waits for a process  to complete (in a separate goroutine).
// Ensure p.Start() has been called prior to calling p.Wait()
func (p *Proc) Wait() *Proc {
	if p.cmd == nil {
		p.err = fmt.Errorf("command is nill")
		return p
	}
	if err := p.cmd.Wait(); err != nil {
		p.err = err
		// use return below to get proc info
	}
	return p.Peek()
}

// Run starts and wait for a process to complete.
// Before calling p.Run(), setup proper access to the process' input/output (i.e. stdin,stdout, stderr)
func (p *Proc) Run() *Proc {
	if p.Start().Err() != nil {
		return p
	}
	return p.Wait()
}

// ID returns process id
func (p *Proc) ID() int {
	return p.id
}

// Exited returns true if process exits ok
func (p *Proc) Exited() bool {
	if p.state == nil {
		return false
	}
	return p.state.Exited()
}

// ExitCode returns process exit code
func (p *Proc) ExitCode() int {
	if p.state == nil {
		return -1
	}
	return p.state.ExitCode()
}

// IsSuccess returns true if proc exit ok
func (p *Proc) IsSuccess() bool {
	if p.state == nil {
		return false
	}
	return p.state.Success()
}

// SysTime returns proc system cpu time
func (p *Proc) SysTime() time.Duration {
	if p.state == nil {
		return -1
	}
	return p.state.SystemTime()
}

// UserTime returns proc user cpu time
func (p *Proc) UserTime() time.Duration {
	if p.state == nil {
		return -1
	}
	return p.state.UserTime()
}

// Err returns any execution error
func (p *Proc) Err() error {
	return p.err
}

// Kill halts the process
func (p *Proc) Kill() *Proc {
	if err := p.cmd.Process.Kill(); err != nil {
		p.err = err
	}
	return p
}

// Out waits, after StartProc or Proc.Start has been called, for the cmd to complete
// and returns the combined result (Stdout and Stderr) as a single reader to be streamed.
func (p *Proc) Out() io.Reader {
	if !p.hasStarted() {
		p.cmd.Stdout = p.result
		p.cmd.Stderr = p.result
		if err := p.Start().Err(); err != nil {
			return strings.NewReader(fmt.Sprintf("proc: out failed: %s", err))
		}
	}

	if !p.Exited() {
		if err := p.Wait().Err(); err != nil {
			return strings.NewReader(fmt.Sprintf("proc: out: failed to wait: %s", err))
		}
	}

	return p.result
}

// Result waits, after proc.Start or proc.StartProc has been called, for the cmd to complete
// and returns the combined stdout and stderr result as a string value.
func (p *Proc) Result() string {
	p.Out()
	if p.Err() != nil {
		return p.Err().Error()
	}
	return strings.TrimSpace(p.result.String())
}

// Stdin returns the standard input stream for the process
func (p *Proc) Stdin() io.Reader {
	return p.cmd.Stdin
}

// SetStdin sets a stream for the process to read its input from
func (p *Proc) SetStdin(in io.Reader) {
	p.cmd.Stdin = in
}

// GetInputPipe returns a stream where the process input can be written to
func (p *Proc) GetInputPipe() io.Writer {
	return p.inputPipe
}

// Stdout returns the standard output stream for the process
func (p *Proc) Stdout() io.Writer {
	return p.cmd.Stdout
}

// SetStdout sets a stream where the process can write its output to
func (p *Proc) SetStdout(out io.Writer) {
	p.cmd.Stdout = out
}

// GetOutputPipe returns a stream where the process output can be read from
func (p *Proc) GetOutputPipe() io.Reader {
	return p.outputPipe
}

// Stderr returns the standard error stream for the process
func (p *Proc) Stderr() io.Writer {
	return p.cmd.Stderr
}

// SetStderr sets a stream where the process can write its errors to
func (p *Proc) SetStderr(out io.Writer) {
	p.cmd.Stderr = out
}

// GetErrorPipe returns a stream where the process error can be read from
func (p *Proc) GetErrorPipe() io.Reader {
	return p.errorPipe
}

func (p *Proc) hasStarted() bool {
	return (p.cmd.Process != nil && p.cmd.Process.Pid != 0)
}
