// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package getevents

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/testutils"
	"github.com/stretchr/testify/assert"
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
		assert.Error(t, err)
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

	t.Run("FilterDeathstart", func(t *testing.T) {
		testutils.MockPipedFile(t, testutils.RepoRootPath("testdata/events.json"))
		cmd := New()
		cmd.SetArgs([]string{"--pods", "deathstar"})
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
		lines := bytes.Split(output, []byte("\n"))
		for _, line := range lines {
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
		lines := bytes.Split(output, []byte("\n"))
		for _, line := range lines {
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
		assert.Equal(t, 2, len(lines))
		for _, line := range lines {
			var res tetragon.GetEventsResponse
			err := json.Unmarshal(line, &res)
			if err != nil {
				t.Fatal(err)
			}
			class, ok := res.GetProcessExec().Process.Pod.PodLabels["class"]
			assert.True(t, ok, "Class label should be present")
			assert.Equal(t, class, "deathstar")
		}
	})
}
