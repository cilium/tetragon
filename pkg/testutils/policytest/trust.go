// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package policytest

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"
)

// getTrustedUIDs returns the users allowed to own the binaries: root and the invoking user.
func getTrustedUIDs() []uint32 {
	uid := uint32(os.Geteuid())
	if uid == 0 {
		if v, err := strconv.ParseUint(os.Getenv("SUDO_UID"), 10, 32); err == nil {
			uid = uint32(v)
		}
	}
	return []uint32{0, uid}
}

// checkTrustedInode checks the owner and permissions of a single path. allowSticky accepts
// writable sticky directories (e.g., /tmp); only used for the parents of the binaries directory.
func checkTrustedInode(path string, inodeInfo os.FileInfo, trustedUIDs []uint32, allowSticky bool) error {
	rawStat, hasRawStat := inodeInfo.Sys().(*syscall.Stat_t)
	if !hasRawStat {
		return fmt.Errorf("unable to determine owner for %s", path)
	}
	if !slices.Contains(trustedUIDs, rawStat.Uid) {
		return fmt.Errorf("%s is not owned by trusted uid", path)
	}
	fileMode := inodeInfo.Mode()
	if allowSticky && fileMode.IsDir() && fileMode&os.ModeSticky != 0 {
		return nil
	}
	const groupOtherWrite = 0o022
	if fileMode.Perm()&groupOtherWrite != 0 {
		return fmt.Errorf("%s is writable by group or other", path)
	}
	return nil
}

// checkTrustedPath checks dir and all its parents, which must all be directories.
// dir must be absolute and free of symlinks.
func checkTrustedPath(dir string, uids []uint32) error {
	for curDir := dir; ; curDir = filepath.Dir(curDir) {
		dirInfo, err := os.Lstat(curDir)
		if err != nil {
			return fmt.Errorf("failed to get %s directory info: %w", curDir, err)
		}
		if !dirInfo.IsDir() {
			return fmt.Errorf("%s is not a directory", curDir)
		}
		if err := checkTrustedInode(curDir, dirInfo, uids, curDir != dir); err != nil {
			return fmt.Errorf("directory permissions verification failed: %w", err)
		}
		if parent := filepath.Dir(curDir); parent == curDir {
			return nil
		}
	}
}

// checkTrustedBinsDir checks that dir (absolute, with symlinks resolved) and every regular file
// in it can only be modified by trusted users.
func checkTrustedBinsDir(dir string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("%s directory must be an absolute path", dir)
	}
	uids := getTrustedUIDs()
	if err := checkTrustedPath(dir, uids); err != nil {
		return fmt.Errorf("check failed for directory and parents: %w", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("failed to list binaries in directory: %w", err)
	}
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return fmt.Errorf("failed to resolve %s: %w", path, err)
		}
		resolvedInfo, err := os.Stat(resolved)
		if err != nil {
			return fmt.Errorf("failed to get info for %s: %w", path, err)
		}
		// subdirectories (e.g., go sources) and special files are never executed
		if !resolvedInfo.Mode().IsRegular() {
			continue
		}
		// symlink pointing outside dir: its directory and parents must be trusted too.
		if resolvedDir := filepath.Dir(resolved); resolvedDir != dir {
			err = checkTrustedPath(resolvedDir, uids)
		}
		if err == nil {
			err = checkTrustedInode(resolved, resolvedInfo, uids, false)
		}
		if err != nil {
			if resolved != path {
				return fmt.Errorf("untrusted file %s -> %w", path, err)
			}
			return fmt.Errorf("untrusted file: %w", err)
		}
	}
	return nil
}
