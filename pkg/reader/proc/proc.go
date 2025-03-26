// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package proc

import (
	"strconv"
	"strings"
)

// Status reflects fields of `/proc/[pid]/status` and other
// fields that we want
type Status struct {
	// Real, effective, saved, and filesystem.
	Uids []string
	Gids []string

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

// Returns all parsed UIDs on success. If we fail for one value we do not
// return the overflow ID, we return the invalid UID 4294967295
// (-1 as an unsigned integer).
// The overflow ID is returned when the kernel decides and pass it back,
// as it can be a valid indication of UID mapping error.
func (status *Status) GetUids() ([]uint32, error) {
	uids := []uint32{InvalidUid, InvalidUid, InvalidUid, InvalidUid}

	for i, v := range status.Uids {
		uid, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return uids, err
		}
		uids[i] = uint32(uid)
	}

	return uids, nil
}

// Returns all parsed GIDs on success. If we fail for one value we do not
// return the overflow ID, we return the invalid UID 4294967295
// (-1 as an unsigned integer).
// The overflow ID is returned when the kernel decides and pass it back,
// as it can be a valid indication of UID mapping error.
func (status *Status) GetGids() ([]uint32, error) {
	gids := []uint32{InvalidUid, InvalidUid, InvalidUid, InvalidUid}

	for i, v := range status.Gids {
		gid, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return gids, err
		}
		gids[i] = uint32(gid)
	}

	return gids, nil
}

// Returns the task loginuid on success, if we fail we return
// the invalid uid 4294967295 that is same value of tasks
// Returns the task loginuid on success, if we fail we return
// the invalid uid 4294967295 that is same value of tasks
// without loginuid.
func (status *Status) GetLoginUid() (uint32, error) {
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
