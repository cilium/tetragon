// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package pidfile

import (
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

func TestIsPidAliveByHandle_CurrentProcess(t *testing.T) {
	// Get current process ID
	pid := os.Getpid()
	// Open a handle to the current process
	hProc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		t.Fatalf("Failed to open process handle: %v", err)
	}
	defer windows.CloseHandle(hProc)

	alive := IsPidAliveByHandle(hProc)
	if !alive {
		t.Errorf("Expected current process to be alive, got false")
	}
}
