// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package pidfile

import (
	"bytes"
	"errors"
	"os"
	"strconv"

	"github.com/cilium/tetragon/pkg/defaults"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/proc"
)

var (
	ErrPidFileAccess   = errors.New("pid file access failed")
	ErrPidIsNotAlive   = errors.New("process is not alive")
	ErrPidIsStillAlive = errors.New("process is already running")
)

func readPidFile() (uint64, error) {
	data, err := os.ReadFile(defaults.DefaultPidFile)
	if err != nil {
		// Let's make this as ErrPidFileAccess error
		// since we don't really care about read errors
		// and this allows to overwrite it later.
		// Our aim is to check if a previous instance is running
		// or not.
		return 0, ErrPidFileAccess
	}

	pid := string(bytes.TrimSpace(data))
	if !isPidAlive(pid) {
		return 0, ErrPidIsNotAlive
	}

	return strconv.ParseUint(pid, 10, 32)
}

// Create() Creates a Pid file
//
// On success returns:
//
//	The current PID and nil on success
//
// On failure returns:
//
//	Returns old pid if still running and PidIsStillAlive error
//	Or returns zero and an error
func Create() (uint64, error) {
	pid, err := readPidFile()
	if err == nil && pid != 0 {
		return pid, ErrPidIsStillAlive
	}

	if err != nil && !errors.Is(err, ErrPidFileAccess) && !errors.Is(err, ErrPidIsNotAlive) {
		return 0, err
	}

	pid, err = proc.GetSelfPid(option.Config.ProcFS)
	if err != nil {
		return 0, err
	}

	return pid, os.WriteFile(defaults.DefaultPidFile, []byte(strconv.FormatUint(pid, 10)), 0o644)
}

func Delete() error {
	return os.Remove(defaults.DefaultPidFile)
}
