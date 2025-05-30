// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package proc

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/cilium/tetragon/pkg/constants"
	"golang.org/x/sys/windows"
)

type TokenGroups struct {
	GroupCount uint32
	Groups     []syscall.SIDAndAttributes
}

type TokenStatistics struct {
	TokenId            windows.LUID
	AuthenticationId   windows.LUID
	ExpirationTime     int64
	TokenType          uint32
	ImpersonationLevel uint32
	DynamicCharged     uint32
	DynamicAvailable   uint32
	GroupCount         uint32
	PrivilegeCount     uint32
	ModifiedId         windows.LUID
}

func getIDFromSID(str_sid string) (string, error) {
	tokens := strings.Split(str_sid, "-")
	if len(tokens) <= 1 {
		return "", fmt.Errorf("could no parse SID %s", str_sid)
	}
	return tokens[len(tokens)-1], nil
}

func getStrLuidFromToken(token windows.Token) (string, error) {

	var size uint32
	err := windows.GetTokenInformation(token, windows.TokenStatistics, nil, 0, &size)
	if !errors.Is(err, syscall.ERROR_INSUFFICIENT_BUFFER) {
		return "", fmt.Errorf("gettokeninformation (size query) failed: %w", err)
	}

	// Allocate buffer and retrieve TokenStatistics
	buffer := make([]byte, size)
	err = windows.GetTokenInformation(token, windows.TokenStatistics, &buffer[0], size, &size)
	if err != nil {
		return "", fmt.Errorf("gettokeninformation failed: %w", err)
	}

	// Cast buffer to TOKEN_STATISTICS
	stats := (*TokenStatistics)(unsafe.Pointer(&buffer[0]))

	luid := *(*uint64)(unsafe.Pointer(&stats.AuthenticationId))
	strLUID := strconv.FormatUint(luid, 10)
	return strLUID, nil

}

// fillStatus returns the content of /proc/pid/status as Status
func fillStatus(hProc windows.Handle, status *Status) error {
	var token windows.Token
	err := windows.OpenProcessToken(hProc, windows.TOKEN_QUERY, &token)
	if err != nil {
		return err
	}

	defer token.Close()
	str_uid, err := getStrLuidFromToken(token)
	if err != nil {
		return err
	}
	status.Uids = []string{str_uid, str_uid, str_uid, str_uid}
	tokenGroup, err := token.GetTokenPrimaryGroup()
	if err != nil {
		return err
	}
	str_groupid := tokenGroup.PrimaryGroup.String()
	if err != nil {
		return err
	}
	str_gid, err := getIDFromSID(str_groupid)
	if err != nil {
		return err
	}
	status.Gids = []string{str_gid, str_gid, str_gid, str_gid}
	return nil
}

func getTokenInfo(t syscall.Token, class uint32, initSize int) (unsafe.Pointer, error) {
	n := uint32(initSize)
	for {
		b := make([]byte, n)
		e := syscall.GetTokenInformation(t, class, &b[0], uint32(len(b)), &n)
		if e == nil {
			return unsafe.Pointer(&b[0]), nil
		}
		if !errors.Is(e, syscall.ERROR_INSUFFICIENT_BUFFER) {
			return nil, e
		}
		if n <= uint32(len(b)) {
			return nil, e
		}
	}
}

func fillLoginUid(hProc windows.Handle, status *Status) error {

	var token syscall.Token
	err := syscall.OpenProcessToken(syscall.Handle(hProc), syscall.TOKEN_QUERY, &token)
	if err != nil {
		return err
	}
	defer token.Close()

	ret, err := getTokenInfo(token, windows.TokenLogonSid, 32)
	if err != nil {
		return err
	}
	tokenGroups := (*TokenGroups)(ret)
	if tokenGroups.GroupCount == 0 {
		return errors.New("login uid not found")
	}

	sidAndAttributes := (*syscall.SIDAndAttributes)(unsafe.Pointer(&tokenGroups.Groups[0]))
	logonSid := (*syscall.SID)(unsafe.Pointer(&sidAndAttributes.Sid))
	sid, err := logonSid.String()
	if err != nil {
		return err
	}
	str_sid, err := getIDFromSID(sid)
	if err != nil {
		return err
	}
	status.LoginUid = str_sid
	return nil
}

func GetStatusFromHandle(hProc windows.Handle) (*Status, error) {
	var status Status

	err := fillStatus(hProc, &status)
	if err != nil {
		return nil, err
	}
	// Fill login UID as sid and change below
	status.LoginUid = status.Uids[0]
	fillLoginUid(hProc, &status)
	return &status, nil
}

func GetStatus(pid uint32) (*Status, error) {
	hProc, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return nil, err
	}
	return GetStatusFromHandle(hProc)
}

func GetProcStatStrings(_ string) ([]string, error) {
	return nil, constants.ErrWindowsNotSupported
}

// GetSelfPid() Get current pid
//
// Returns:
//
//	Current pid from procfs and nil on success
//	Zero and error on failure
func GetSelfPid(_ string) (uint64, error) {
	return uint64(windows.GetCurrentProcessId()), nil
}
