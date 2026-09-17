// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package logger

import (
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestFatalExitCode asserts that Fatal terminates the process with the
// conventional exit status 1, matching every other fatal path in this repo.
func TestFatalExitCode(t *testing.T) {
	if os.Getenv("TETRAGON_TEST_LOGGER_FATAL") == "1" {
		Fatal(GetLogger(), "boom")
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestFatalExitCode")
	cmd.Env = append(os.Environ(), "TETRAGON_TEST_LOGGER_FATAL=1")
	err := cmd.Run()

	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr)
	require.Equal(t, 1, exitErr.ExitCode())
}
