// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package fileutils

import (
	"errors"
	"os"
	"strconv"
	"syscall"
)

const (
	regularSecure os.FileMode = syscall.S_IFREG | 0600
	avoidMask     os.FileMode = 0113
)

// RegularFilePerms() takes an octal string representation and returns
// a FileMode permission.
//
// If the string can not be parsed into a 32 bit unsigned octal, or if
// the passed string is not for a regular file then an error is returned,
// and the default regularSecure file mode is returned.
//
// This functions ensures that it never returns a world writable permission and
// that the owner always has read/write permissions
func RegularFilePerms(s string) (os.FileMode, error) {
	if s == "" {
		return regularSecure, errors.New("passed permissions are empty")
	}

	n, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return regularSecure, err
	}

	// clear out mode flags and ensure avoidMask perms are not set
	mode := (os.FileMode(n) & os.FileMode(0000777)) & ^avoidMask

	mode |= regularSecure
	return mode, nil
}
