// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package procevents

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/tetragon/pkg/option"
)

// procDockerId reads the pid cgroup from proc and returns the container ID.
// pid argument is the pid of the target process
// Returns the container ID and nil on success, or an empty string if it fails to identify
// the container ID or if an error happens. If the pid is unavailable, an error will be
// returned.
func procsDockerId(pid uint32) (string, error) {
	pidstr := fmt.Sprint(pid)
	cgroups, err := os.ReadFile(filepath.Join(option.Config.ProcFS, pidstr, "cgroup"))
	if err != nil {
		return "", err
	}
	off, _ := procsFindDockerId(string(cgroups))
	return off, nil
}
