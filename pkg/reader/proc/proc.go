// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package proc

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Status reflects fields of `/proc/[pid]/status` and other
// fields that we want
type Status struct {
	// Real, effective, saved, and filesystem.
	Uids []string

	// /proc/[pid]/loginuid
	LoginUid string
}

const (
	nanoPerSeconds = 1000000000

	// CLK_TCK is always constant 100 on all architectures except alpha and ia64 which are both
	// obsolete and not supported by Tetragon. Also see
	// https://lore.kernel.org/lkml/agtlq6$iht$1@penguin.transmeta.com/ and
	// https://github.com/containerd/cgroups/pull/12
	clktck = uint64(100)

	// Linux UIDs range from 0..4294967295, the initial mapping of user IDs is 0:0:4294967295.
	//
	// If Tetragon is not run in this initial mapping due to user namespaces or runtime
	// modifications then reading uids of pids from /proc may return the overflow UID 65534
	// if the mapping config where Tetragon is running does not have a mapping of the
	// uid of the target pid.
	// The overflow UID is runtime config at /proc/sys/kernel/{overflowuid,overflowgid}.
	//
	// The overflow UID historically is also the "nobody" UID, so there is some confusion
	// there. Tetragon may get overflowuid from kernel but users could confuse this with
	// the "nobody" user that some distributions use.
	//
	// The UID 4294967295 (-1 as an unsigned integer) is an invalid UID, the kernel
	// ignores and return it in some cases where there is no mapping or to indicate
	// an invalid UID. So we use it to initialize our UIDs and return it on errors.
	InvalidUid = ^uint32(0) // 4294967295 (2^32 - 1)
)

// The /proc/PID/stat file consists of a single line of space-separated strings, where
// the 2nd string contains the process' comm. This string is wrapped in brackets but can
// contain spaces and brackets. The correct way to parse this stat string is to find all
// space-separated strings working backwards from the end until a string is found that
// ends in a space, then find the first string and everything left must be the comm.
func getProcStatStrings(procStat string) []string {
	var output []string

	// Build list of strings in reverse order
	oldIndex := len(procStat)
	index := strings.LastIndexByte(procStat, ' ')
	for index > 0 {
		output = append(output, procStat[index+1:oldIndex])
		if procStat[index-1] == ')' {
			break
		}
		oldIndex = index
		index = strings.LastIndexByte(procStat[:oldIndex], ' ')
	}

	if index == -1 {
		// Did not hit ')'
		output = append(output, procStat[:oldIndex])
	} else {
		// Find the comm and first field
		commIndex := strings.IndexByte(procStat, ' ')
		output = append(output, procStat[commIndex+1:index])
		output = append(output, procStat[:commIndex])
	}

	// Reverse the array
	for i, j := 0, len(output)-1; i < j; i, j = i+1, j-1 {
		output[i], output[j] = output[j], output[i]
	}

	return output
}

// fillStatus returns the content of /proc/pid/status as Status
func fillStatus(file string, status *Status) error {
	path := filepath.Join(file, "status")
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("Open %s failed: %v", path, err)
	}

	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)

		if len(fields) < 2 {
			continue
		}

		if fields[0] == "Uid:" {
			if len(fields) != 5 {
				return fmt.Errorf("Reading Uid from %s failed: malformed input", path)
			}
			status.Uids = []string{fields[1], fields[2], fields[3], fields[4]}
			break
		}
	}

	return nil
}

func fillLoginUid(file string, status *Status) error {
	path := filepath.Join(file, "loginuid")
	auid, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("ReadFile %s failed: %v", path, err)
	}

	status.LoginUid = strings.TrimRight(string(auid), "\n")

	return nil
}

func GetStatus(file string) (*Status, error) {
	var status Status
	err := fillStatus(file, &status)
	if err != nil {
		return nil, err
	}

	err = fillLoginUid(file, &status)
	if err != nil {
		return nil, err
	}

	return &status, nil
}

func GetProcStatStrings(file string) ([]string, error) {
	statline, err := os.ReadFile(filepath.Join(file, "stat"))
	if err != nil {
		return nil, fmt.Errorf("ReadFile: %s /stat error", file)
	}
	return getProcStatStrings(string(statline)), nil
}

func GetStatsKtime(s []string) (uint64, error) {
	ktime, err := strconv.ParseUint(s[21], 10, 64)
	if err != nil {
		return 0, err
	}
	return ktime * (nanoPerSeconds / clktck), nil
}

func GetProcPid(pid string) (uint64, error) {
	return strconv.ParseUint(pid, 10, 32)
}

// Returns real uid and effective uid on success. If we fail we do not
// return the overflow ID, we return the invalid UID 4294967295
// (-1 as an unsigned integer).
// The overflow ID is returned when the kernel decides and pass it back,
// as it can be a valid indication of UID mapping error.
func GetUids(status *Status) (uint32, uint32, error) {
	ruid, err := strconv.ParseUint(status.Uids[0], 10, 32)
	if err != nil {
		return InvalidUid, InvalidUid, err
	}

	euid, err := strconv.ParseUint(status.Uids[1], 10, 32)
	if err != nil {
		return InvalidUid, InvalidUid, err
	}

	return uint32(ruid), uint32(euid), nil
}

// Returns the task loginuid on success, if we fail we return
// the invalid uid 4294967295 that is same value of tasks
// without loginuid.
func GetLoginUid(status *Status) (uint32, error) {
	auid, err := strconv.ParseUint(status.LoginUid, 10, 32)
	if err != nil {
		return InvalidUid, err
	}

	return uint32(auid), nil
}

func PrependPath(s string, b []byte) []byte {
	split := strings.Split(string(b), "\u0000")
	split[0] = s
	fullCmd := strings.Join(split[0:], "\u0000")
	return []byte(fullCmd)
}
