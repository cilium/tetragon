package proc

import (
	"fmt"
	"os"
	"syscall"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/windows"
)

func TestGetProcStatStrings(t *testing.T) {
	pid := os.Getpid() // Get the current process's PID

	status, err := GetStatus(uint32(pid))
	assert.Equal(t, err, nil)
	t.Log("User = ", status.Uids)
	t.Log("Group = ", status.Gids)
	t.Log("LoginUId = ", status.LoginUid)
}

func TestFillLoginUid(t *testing.T) {
	pid := os.Getpid() // Get the current process's PID

	c, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	assert.Equal(t, err, nil)
	defer windows.CloseHandle(c)

	var token syscall.Token
	err = syscall.OpenProcessToken(syscall.Handle(c), syscall.TOKEN_QUERY, &token)
	assert.Equal(t, err, nil)
	defer token.Close()
	var logonSid *TokenGroups

	ret, err := getTokenInfo(token, windows.TokenLogonSid, 32)
	assert.Equal(t, err, nil)
	logonSid = (*TokenGroups)(ret)
	tokenUser := (*syscall.SIDAndAttributes)(unsafe.Pointer(&logonSid.Groups[0]))
	sid := (*syscall.SID)(unsafe.Pointer(&tokenUser.Sid))
	str, err1 := sid.String()
	assert.Equal(t, err1, nil)
	fmt.Printf("SID = %s", str)
}
