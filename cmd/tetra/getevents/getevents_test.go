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

func Test_GetEvents_Namespace(t *testing.T) {
	t.Run("FilterNothing", func(t *testing.T) {
		testutils.MockPipedFile(t, testutils.RepoRootPath("testdata/events.json"))
		cmd := New()
		cmd.SetArgs([]string{"--namespace", "default"})
		output := testutils.RedirectStdoutExecuteCmd(t, cmd)
		assert.Equal(t, 3, bytes.Count(output, []byte("\n")))
	})

	t.Run("FilterAll", func(t *testing.T) {
		testutils.MockPipedFile(t, testutils.RepoRootPath("testdata/events.json"))
		cmd := New()
		cmd.SetArgs([]string{"--namespace", "doesnotexist"})
		output := testutils.RedirectStdoutExecuteCmd(t, cmd)
		assert.Equal(t, 0, bytes.Count(output, []byte("\n")))
	})
}

func Test_GetEvents_Pod(t *testing.T) {
	t.Run("FilterTie", func(t *testing.T) {
		testutils.MockPipedFile(t, testutils.RepoRootPath("testdata/events.json"))
		cmd := New()
		cmd.SetArgs([]string{"--pod", "tiefighter"})
		output := testutils.RedirectStdoutExecuteCmd(t, cmd)
		assert.Equal(t, 1, bytes.Count(output, []byte("\n")))
	})

	t.Run("FilterDeathstart", func(t *testing.T) {
		testutils.MockPipedFile(t, testutils.RepoRootPath("testdata/events.json"))
		cmd := New()
		cmd.SetArgs([]string{"--pod", "deathstar"})
		output := testutils.RedirectStdoutExecuteCmd(t, cmd)
		assert.Equal(t, 2, bytes.Count(output, []byte("\n")))
	})
}

func Test_GetEvents_Process(t *testing.T) {
	t.Run("FilterNetserver", func(t *testing.T) {
		testutils.MockPipedFile(t, testutils.RepoRootPath("testdata/events.json"))
		cmd := New()
		cmd.SetArgs([]string{"--process", "netserver"})
		output := testutils.RedirectStdoutExecuteCmd(t, cmd)
		assert.Equal(t, 1, bytes.Count(output, []byte("\n")))
	})

	t.Run("FilterDocker", func(t *testing.T) {
		testutils.MockPipedFile(t, testutils.RepoRootPath("testdata/events.json"))
		cmd := New()
		cmd.SetArgs([]string{"--process", "docker"})
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
}
