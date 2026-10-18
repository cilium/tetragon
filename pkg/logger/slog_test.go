// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package logger

import (
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFatalExitCode(t *testing.T) {
	if os.Getenv("TETRAGON_FATAL_CHILD") == "1" {
		// Child process: the default no-op exit handler is active
		// (RegisterExitHandler has no in-repo callers), so this
		// exercises exactly the production path of Fatal.
		Fatal(GetLogger(), "test fatal")
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestFatalExitCode")
	cmd.Env = append(os.Environ(), "TETRAGON_FATAL_CHILD=1")
	err := cmd.Run()
	require.Error(t, err)
	require.Equal(t, 1, cmd.ProcessState.ExitCode())
}
