// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/testutils"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func validatePipe2Event(t *testing.T, fds [2]int, expectedCount int) {
	exportFile, err := testutils.GetExportFilename(t)
	require.NoError(t, err)

	f, err := os.Open(exportFile)
	require.NoError(t, err)
	defer f.Close()

	dec := json.NewDecoder(f)
	found := false
	for dec.More() {
		var event tetragon.GetEventsResponse
		if err := dec.Decode(&event); err != nil {
			t.Logf("Decode incorrect: %v", err)
			continue
		}

		kp := event.GetProcessKprobe()
		if kp == nil {
			continue
		}

		if !strings.HasSuffix(kp.FunctionName, "sys_pipe2") {
			continue
		}

		// Verify Args
		if len(kp.Args) < 1 {
			t.Errorf("Expected args, got none")
			continue
		}

		// Arg 0 should be Int32ListArg
		arg0 := kp.Args[0]
		listArg := arg0.GetInt32ListArg()
		if listArg == nil {
			t.Errorf("Expected Int32ListArg at index 0, got %T", arg0.Arg)
			continue
		}

		if len(listArg.Values) != expectedCount {
			t.Logf("Skipping event with unexpected value count: %d (expected %d)", len(listArg.Values), expectedCount)
			continue
		}

		// Verify values match FDs for the available count
		match := true
		for i := 0; i < expectedCount && i < 2; i++ {
			if listArg.Values[i] != int32(fds[i]) {
				t.Logf("Value mismatch at index %d: expected %d, got %d", i, fds[i], listArg.Values[i])
				match = false
				break
			}
		}
		if !match {
			continue
		}

		found = true
		break
	}

	require.True(t, found, "Did not find matching pipe2 event in export file with expected count %d", expectedCount)
}

func TestKprobePipe2Return(t *testing.T) {
	tus.Conf().DisableTetragonLogs = true
	pidStr := strconv.Itoa(int(observertesthelper.GetMyPid()))

	tests := []struct {
		name          string
		yamlSize      string
		expectedCount int
	}{
		{
			name:          "No size (default 0)",
			yamlSize:      "",
			expectedCount: 0,
		},
		{
			name:          "Size 1",
			yamlSize:      "size: 1",
			expectedCount: 1,
		},
		{
			name:          "Size 2",
			yamlSize:      "size: 2",
			expectedCount: 2,
		},
		{
			name:          "Size 5",
			yamlSize:      "size: 5",
			expectedCount: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var doneWG, readyWG sync.WaitGroup
			defer doneWG.Wait()

			ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
			defer cancel()

			t.Logf("tester pid=%s\n", pidStr)

			pipe2ConfigHook := `
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "pipe2-test"
spec:
  kprobes:
  - call: "sys_pipe2"
    syscall: true
    args:
    - index: 0
      type: "int32_arr"
      ` + tt.yamlSize + `
      returnCopy: true
      label: "pipefd"
    - index: 1
      type: "int"
      label: "flags"
    selectors:
    - matchPIDs:
      - operator: In
        followForks: true
        values:
        - ` + pidStr

			tmpFile, err := os.CreateTemp(t.TempDir(), "tetragon-config-*.yaml")
			if err != nil {
				t.Fatalf("createTemp: err %s", err)
			}
			testConfigFile := tmpFile.Name()
			defer os.Remove(testConfigFile)

			if _, err := tmpFile.Write([]byte(pipe2ConfigHook)); err != nil {
				t.Fatalf("write temp file: err %s", err)
			}
			if err := tmpFile.Close(); err != nil {
				t.Fatalf("close temp file: err %s", err)
			}

			obs, err := observertesthelper.GetDefaultObserverWithFile(t, ctx, testConfigFile, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
			if err != nil {
				t.Fatalf("GetDefaultObserverWithFile error: %s", err)
			}

			observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
			readyWG.Wait()

			var fds [2]int
			if err := unix.Pipe2(fds[:], unix.O_CLOEXEC); err != nil {
				t.Fatalf("unix.Pipe2 failed: %v", err)
			}
			defer unix.Close(fds[0])
			defer unix.Close(fds[1])

			t.Logf("Expected FDs: %v", fds)
			time.Sleep(2 * time.Second) // Reduced wait time since we are running multiple tests

			validatePipe2Event(t, fds, tt.expectedCount)
		})
	}
}
