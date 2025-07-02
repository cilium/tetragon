// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package pidfile

import (
	"strconv"

	"golang.org/x/sys/windows"
)

const (
	INVALID_HANDLE_VALUE = windows.Handle(^uintptr(0))
)

func IsPidAliveByHandle(hProc windows.Handle) bool {
	var exitCode uint32
	err := windows.GetExitCodeProcess(hProc, &exitCode)
	if err != nil {
		return false // error occurred while querying process state
	}
	return exitCode == 259
}
func IsPidAlive(pid int32) bool {

	if (pid == 4) || (pid == 0) {
		return true // pid 0(kernel) and 4(system) are always alive
	}
	hProc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if hProc == INVALID_HANDLE_VALUE {
		return false // process does not exist
	}
	defer windows.CloseHandle(hProc)
	if err != nil {
		return false
	}
	return IsPidAliveByHandle(hProc)
}

func isPidAlive(pid string) bool {
	int32pid, err := strconv.ParseInt(pid, 0, 32)
	return err == nil && IsPidAlive(int32(int32pid))
}
