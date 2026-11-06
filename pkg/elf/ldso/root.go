// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build linux

package ldso

import (
	"os"
	"path/filepath"
)

// Root is the filesystem a binary and its dependencies are resolved in.
//
// Every path passed to a Root is an absolute path as seen from inside that
// root (e.g. "/usr/lib/libc.so.6"), and every path returned by the resolver
// is expressed the same way. Implementations are responsible for making sure
// lookups, including symlink resolution, cannot escape the root.
type Root interface {
	// Open opens path for reading.
	Open(path string) (*os.File, error)
	// RealPath returns path with all symlinks resolved.
	RealPath(path string) (string, error)
}

type hostRoot struct{}

// HostRoot returns a Root for the filesystem Tetragon itself sees.
func HostRoot() Root {
	return hostRoot{}
}

func (hostRoot) Open(path string) (*os.File, error) {
	return os.Open(path)
}

func (hostRoot) RealPath(path string) (string, error) {
	return filepath.EvalSymlinks(path)
}
