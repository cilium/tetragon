// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package getevents

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/testutils"
)

func Test_GetEvents_Namespaces(t *testing.T) {
	t.Run("FilterNothing", func(t *testing.T) {
		testutils.MockPipedFile(t, testutils.RepoRootPath("testdata/events.json"))
		cmd := New()
		cmd.SetArgs([]string{"--namespaces", "default"})
		output := testutils.RedirectStdoutExecuteCmd(t, cmd)
		assert.Equal(t, 3, bytes.Count(output, []byte("\n")))
	})

	t.Run("FilterAll", func(t *testing.T) {
		testutils.MockPipedFile(t, testutils.RepoRootPath("testdata/events.json"))
		cmd := New()
		cmd.SetArgs([]string{"--namespaces", "doesnotexist"})
		output := testutils.RedirectStdoutExecuteCmd(t, cmd)
		assert.Equal(t, 0, bytes.Count(output, []byte("\n")))
	})
}

func Test_GetEvents_EventTypes(t *testing.T) {
	t.Run("FilterProcessExec", func(t *testing.T) {
		testutils.MockPipedFile(t, testutils.RepoRootPath("testdata/events.json"))
		cmd := New()
		cmd.SetArgs([]string{"--event-types", "PROCESS_EXEC"})
		output := testutils.RedirectStdoutExecuteCmd(t, cmd)
		assert.Equal(t, 3, bytes.Count(output, []byte("\n")))
	})

	t.Run("FilterInexistent", func(t *testing.T) {
		cmd := New()
		cmd.SetArgs([]string{"--event-types", "INEXISTENT"})

		// redirect stderr and stdout to not pollute test outputs. Here it
		// works, compared to other use case where we have to redirect manually,
		// because Cobra internal error mechanism calls internal Print methods.
		var devNull bytes.Buffer
		cmd.SetErr(&devNull)
		cmd.SetOut(&devNull)

		err := cmd.Execute()
		require.Error(t, err)
	})

	t.Run("FilterInexistentSortedError", func(t *testing.T) {
		cmd := New()
		cmd.SetArgs([]string{"--event-types", "INEXISTENT"})

		var devNull bytes.Buffer
		cmd.SetErr(&devNull)
		cmd.SetOut(&devNull)

		err := cmd.Execute()
		require.Error(t, err)
		msg := err.Error()
		// Supported event types must be listed in alphabetical order.
		require.Less(t, strings.Index(msg, "PROCESS_EXEC"), strings.Index(msg, "PROCESS_EXIT"),
			"PROCESS_EXEC should appear before PROCESS_EXIT in sorted output")
		require.Less(t, strings.Index(msg, "PROCESS_EXIT"), strings.Index(msg, "UNDEF"),
			"PROCESS_EXIT should appear before UNDEF in sorted output")
	})
}

func Test_GetEvents_Pods(t *testing.T) {
	t.Run("FilterTie", func(t *testing.T) {
		testutils.MockPipedFile(t, testutils.RepoRootPath("testdata/events.json"))
		cmd := New()
		cmd.SetArgs([]string{"--pods", "tiefighter"})
		output := testutils.RedirectStdoutExecuteCmd(t, cmd)
		assert.Equal(t, 1, bytes.Count(output, []byte("\n")))
	})

	t.Run("FilterDeathstar", func(t *testing.T) {
		testutils.MockPipedFile(t, testutils.RepoRootPath("testdata/events.json"))
		cmd := New()
		cmd.SetArgs([]string{"--pods", "deathstar"})
		output := testutils.RedirectStdoutExecuteCmd(t, cmd)
		assert.Equal(t, 2, bytes.Count(output, []byte("\n")))
	})
}

func Test_GetEvents_Containers(t *testing.T) {
	t.Run("FilterTie", func(t *testing.T) {
		testutils.MockPipedFile(t, testutils.RepoRootPath("testdata/events.json"))
		cmd := New()
		cmd.SetArgs([]string{"--containers", "spaceship"})
		output := testutils.RedirectStdoutExecuteCmd(t, cmd)
		assert.Equal(t, 1, bytes.Count(output, []byte("\n")))
	})

	t.Run("FilterDeath*", func(t *testing.T) {
		testutils.MockPipedFile(t, testutils.RepoRootPath("testdata/events.json"))
		cmd := New()
		cmd.SetArgs([]string{"--containers", "death*"})
		output := testutils.RedirectStdoutExecuteCmd(t, cmd)
		assert.Equal(t, 2, bytes.Count(output, []byte("\n")))
	})
}

func Test_GetEvents_Processes(t *testing.T) {
	t.Run("FilterNetserver", func(t *testing.T) {
		testutils.MockPipedFile(t, testutils.RepoRootPath("testdata/events.json"))
		cmd := New()
		cmd.SetArgs([]string{"--processes", "netserver"})
		output := testutils.RedirectStdoutExecuteCmd(t, cmd)
		assert.Equal(t, 1, bytes.Count(output, []byte("\n")))
	})

	t.Run("FilterDocker", func(t *testing.T) {
		testutils.MockPipedFile(t, testutils.RepoRootPath("testdata/events.json"))
		cmd := New()
		cmd.SetArgs([]string{"--processes", "docker"})
		output := testutils.RedirectStdoutExecuteCmd(t, cmd)
		assert.Equal(t, 2, bytes.Count(output, []byte("\n")))
	})
}

func Test_GetEvents_FilterFields(t *testing.T) {
	t.Run("ExcludeParent", func(t *testing.T) {
		testutils.MockPipedFile(t, testutils.RepoRootPath("testdata/events.json"))
		cmd := New()
		cmd.SetArgs([]string{"-F", "parent"})
		output := testutils.RedirectStdoutExecuteCmd(t, cmd)
		// remove last trailing newline for splitting
		output = bytes.TrimSpace(output)
		lines := bytes.SplitSeq(output, []byte("\n"))
		for line := range lines {
			var res tetragon.GetEventsResponse
			err := json.Unmarshal(line, &res)
			if err != nil {
				t.Fatal(err)
			}
			assert.NotEmpty(t, res.GetProcessExec().Process)
			assert.Empty(t, res.GetProcessExec().Parent)
		}
	})

	t.Run("IncludeParent", func(t *testing.T) {
		testutils.MockPipedFile(t, testutils.RepoRootPath("testdata/events.json"))
		cmd := New()
		cmd.SetArgs([]string{"-f", "parent"})
		output := testutils.RedirectStdoutExecuteCmd(t, cmd)
		// remove last trailing newline for splitting
		output = bytes.TrimSpace(output)
		lines := bytes.SplitSeq(output, []byte("\n"))
		for line := range lines {
			var res tetragon.GetEventsResponse
			err := json.Unmarshal(line, &res)
			if err != nil {
				t.Fatal(err)
			}
			assert.Empty(t, res.GetProcessExec().Process)
			assert.NotEmpty(t, res.GetProcessExec().Parent)
		}
	})

	t.Run("FilterCelExpression", func(t *testing.T) {
		testutils.MockPipedFile(t, testutils.RepoRootPath("testdata/events.json"))
		cmd := New()
		cmd.SetArgs([]string{"--cel-expression", "process_exec.process.pod.pod_labels['class'] == 'deathstar'"})
		output := testutils.RedirectStdoutExecuteCmd(t, cmd)
		// remove last trailing newline for splitting
		output = bytes.TrimSpace(output)
		lines := bytes.Split(output, []byte("\n"))
		assert.Len(t, lines, 2)
		for _, line := range lines {
			var res tetragon.GetEventsResponse
			err := json.Unmarshal(line, &res)
			if err != nil {
				t.Fatal(err)
			}
			class, ok := res.GetProcessExec().Process.Pod.PodLabels["class"]
			assert.True(t, ok, "Class label should be present")
			assert.Equal(t, "deathstar", class)
		}
	})
}

func Test_GetEvents_ClosedStdinNoNilPanic(t *testing.T) {
	oldStdin := os.Stdin
	t.Cleanup(func() { os.Stdin = oldStdin })

	// os.NewFile with an invalid fd causes Stat() to return (nil, error).
	// Before the fix RunE would panic on fi.Mode() when fi is nil.
	os.Stdin = os.NewFile(^uintptr(0), "closed")

	cmd := New()
	cmd.SetArgs([]string{})
	var buf bytes.Buffer
	cmd.SetErr(&buf)
	cmd.SetOut(&buf)

	// Must not panic; falls through to gRPC and gets a connection error instead.
	require.NotPanics(t, func() { cmd.Execute() })
}

func Test_GetEvents_RegularFileStdin(t *testing.T) {
	oldStdin := os.Stdin
	t.Cleanup(func() { os.Stdin = oldStdin })

	events, err := os.Open(testutils.RepoRootPath("testdata/events.json"))
	require.NoError(t, err)
	t.Cleanup(func() { events.Close() })
	os.Stdin = events

	cmd := New()
	output := testutils.RedirectStdoutExecuteCmd(t, cmd)
	assert.Equal(t, 3, bytes.Count(output, []byte("\n")))
}
