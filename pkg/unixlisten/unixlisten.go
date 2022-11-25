// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package unixlisten

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// ListenWithRename creates a "unix" listener for the given path and the given mode
//
// Go's net.Listen() performs three system calls at once:
//  - socket, where the file descriptor is created
//  - bind, where the unix socket file is created
//  - listen, where the socket can now accept connections
//
// Hence, doing a chmod(2) after Listen is racy because a client can connect
// between the listen(2) and the chmod(2) calls. One solution would be to use
// umask(2), but this is tricky to do in a multi-threaded program because it
// affects other files being created from different threads. Also, other
// threads may change the umask.
//
// This function, instead, creates the socket file in a private directory,
// performs the appropriate chmod and only then  moves the file to its original
// location. Not sure about other systems, but at least on Linux renaming a
// unix socket file after the listen seems to work without issues.
func ListenWithRename(path string, mode os.FileMode) (net.Listener, error) {
	os.Remove(path)

	baseName := filepath.Base(path)
	dirName := filepath.Dir(path)

	// Create a temporary directory: MkdirTemp creates the directory with 0700
	tmpDir, err := os.MkdirTemp(dirName, fmt.Sprintf("%s-dir-*", baseName))
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	tmpPath := filepath.Join(tmpDir, baseName)
	l, err := net.Listen("unix", tmpPath)
	if err != nil {
		return nil, err
	}

	if err := os.Chmod(tmpPath, mode); err != nil {
		return nil, err
	}

	err = os.Rename(tmpPath, path)
	if err != nil {
		return nil, err
	}
	return l, nil
}
