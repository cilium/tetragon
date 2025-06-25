// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package proc

import (
	"os"
	"syscall"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestGetProcStatStrings(t *testing.T) {
	pid := os.Getpid() // Get the current process's PID

	status, err := GetStatus(uint32(pid))
	require.NoError(t, err)
	t.Log("User = ", status.Uids)
	t.Log("Group = ", status.GIDs)
	t.Log("LoginUId = ", status.LoginUID)
}

func TestFillLoginUid(t *testing.T) {
	pid := os.Getpid() // Get the current process's PID

	c, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	require.NoError(t, err)
	defer windows.CloseHandle(c)

	var token syscall.Token
	err = syscall.OpenProcessToken(syscall.Handle(c), syscall.TOKEN_QUERY, &token)
	require.NoError(t, err)
	defer token.Close()
	var logonSid *TokenGroups

	ret, err := getTokenInfo(token, windows.TokenLogonSid, 32)
	require.NoError(t, err)
	logonSid = (*TokenGroups)(ret)
	tokenUser := (*syscall.SIDAndAttributes)(unsafe.Pointer(&logonSid.Groups[0]))
	sid := (*syscall.SID)(unsafe.Pointer(&tokenUser.Sid))
	str, err1 := sid.String()
	require.NoError(t, err1)
	t.Logf("SID = %s", str)
}
