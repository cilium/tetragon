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
	ErrPIDFileAccess   = errors.New("pid file access failed")
	ErrPIDIsNotAlive   = errors.New("process is not alive")
	ErrPIDIsStillAlive = errors.New("process is already running")
)

func readPIDFile() (uint64, error) {
	data, err := os.ReadFile(defaults.DefaultPIDFile)
	if err != nil {
		// Let's make this as ErrPidFileAccess error
		// since we don't really care about read errors
		// and this allows to overwrite it later.
		// Our aim is to check if a previous instance is running
		// or not.
		return 0, ErrPIDFileAccess
	}

	pid := string(bytes.TrimSpace(data))
	if !isPIDAlive(pid) {
		return 0, ErrPIDIsNotAlive
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
	pid, err := readPIDFile()
	if err == nil && pid != 0 {
		return pid, ErrPIDIsStillAlive
	}

	if err != nil && !errors.Is(err, ErrPIDFileAccess) && !errors.Is(err, ErrPIDIsNotAlive) {
		return 0, err
	}

	pid, err = proc.GetSelfPID(option.Config.ProcFS)
	if err != nil {
		return 0, err
	}

	return pid, os.WriteFile(defaults.DefaultPIDFile, []byte(strconv.FormatUint(pid, 10)), 0o644)
}

func Delete() error {
	return os.Remove(defaults.DefaultPIDFile)
}
