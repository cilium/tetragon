// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package testutils

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

type LseekPipeCmd struct {
	Cmd   *exec.Cmd
	Pipes *CmdBufferedPipes
}

// starts a new lseek-pipe command
//
//revive:disable:context-as-argument
func NewLseekPipe(t *testing.T, ctx context.Context) *LseekPipeCmd {
	bin := RepoRootPath("contrib/tester-progs/lseek-pipe")
	cmd := exec.CommandContext(ctx, bin)
	pipes, err := NewCmdBufferedPipes(cmd)
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		pipes.Close()
		t.Fatal(err)
	}

	return &LseekPipeCmd{
		Cmd:   cmd,
		Pipes: pipes,
	}
}

//revive:enable:context-as-argument

func (lp *LseekPipeCmd) Pid() int {
	return lp.Cmd.Process.Pid
}

func (lp *LseekPipeCmd) Lseek(fd int, offset int64, whence int) string {
	lp.Pipes.P.Stdin.Write([]byte(fmt.Sprintf("%d %d %d\n", fd, offset, whence)))
	// NB: read the result from the lseek-pipe program. Doing so means that
	// whenever we return, we know that the lseek syscall has been
	// executed.
	line, _ := lp.Pipes.StdoutRd.ReadString('\n')
	return strings.TrimSuffix(line, "\n")
}

func (lp *LseekPipeCmd) Close() error {
	lp.Pipes.Close()
	return lp.Cmd.Wait()
}
