// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package checkprocfs

import (
	"path/filepath"
	"syscall"

	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/logger/logfields"
	"github.com/cilium/tetragon/pkg/option"
)

// Check tries to determine whether the configured procfs is the host's procfs
func Check() {

	path := filepath.Join(option.Config.ProcFS, "1", "ns", "pid")
	var stat syscall.Stat_t
	if err := syscall.Stat(path, &stat); err != nil {
		logger.GetLogger().Info("stat failed", "path", path, logfields.Error, err)
	}

	// we compare against the known inode of the host pid namespace:
	// ...
	// 	PROC_PID_INIT_INO	= 0xEFFFFFFCU,
	// ...
	expectedIno := uint64(0xEFFFFFFC)
	if stat.Ino != expectedIno {
		logger.GetLogger().Warn("inode mismatch: procfs does not appear to be host procfs",
			"path", path,
			"inode", stat.Ino,
			"expected inode", expectedIno)
	}
}
