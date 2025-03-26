// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package proc

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type TokenGroups struct {
	GroupCount uint32
	Groups     []syscall.SIDAndAttributes
}

func getIDFromSID(str_sid string) (string, error) {
	tokens := strings.Split(str_sid, "-")
	if len(tokens) <= 1 {
		return "", fmt.Errorf("Could no parse SID %s", str_sid)
	}
	return tokens[len(tokens)-1], nil
}

// fillStatus returns the content of /proc/pid/status as Status
func fillStatus(hProc windows.Handle, status *Status) error {
	var token syscall.Token
	err := syscall.OpenProcessToken(syscall.Handle(hProc), syscall.TOKEN_QUERY, &token)
	if err != nil {
		return err
	}

	defer token.Close()
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	sid_string, err := tokenUser.User.Sid.String()
	if err != nil {
		return err
	}
	str_uid, err := getIDFromSID(sid_string)
	if err != nil {
		return err
	}
	status.Uids = []string{str_uid, str_uid, str_uid, str_uid}
	tokenGroup, err := token.GetTokenPrimaryGroup()
	if err != nil {
		return err
	}
	str_groupid, err := tokenGroup.PrimaryGroup.String()
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
		if e != syscall.ERROR_INSUFFICIENT_BUFFER {
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
		return fmt.Errorf("login uid not found")
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

func GetProcStatStrings(file string) ([]string, error) {
	return nil, fmt.Errorf(" Not supported on Windows")
}

// GetSelfPid() Get current pid
//
// Returns:
//
//	Current pid from procfs and nil on success
//	Zero and error on failure
func GetSelfPid(procfs string) (uint64, error) {
	return uint64(windows.GetCurrentProcessId()), nil
}
