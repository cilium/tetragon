// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package bpf

import "fmt"

func HasOverrideHelper() bool {
	return false
}

func HasSignalHelper() bool {
	return false
}

func HasKprobeMulti() bool {
	return false
}

func HasUprobeMulti() bool {
	return false
}

func HasBuildId() bool {
	return false
}

func HasModifyReturn() bool {
	return false
}

func HasModifyReturnSyscall() bool {
	return false
}
func HasProgramLargeSize() bool {
	return false
}

func HasLSMPrograms() bool {
	return false
}

func HasLinkPin() bool {
	return false
}

func HasMissedStatsPerfEvent() bool {
	return false
}

func HasMissedStatsKprobeMulti() bool {
	return false
}

func LogFeatures() string {
	return fmt.Sprintf("override_return: %t, buildid: %t, kprobe_multi: %t, uprobe_multi %t, fmodret: %t, fmodret_syscall: %t, signal: %t, large: %t, link_pin: %t, lsm: %t, missed_stats_kprobe_multi: %t, missed_stats_kprobe: %t",
		HasOverrideHelper(), HasBuildId(), HasKprobeMulti(), HasUprobeMulti(),
		HasModifyReturn(), HasModifyReturnSyscall(), HasSignalHelper(), HasProgramLargeSize(),
		HasLinkPin(), HasLSMPrograms(), HasMissedStatsKprobeMulti(), HasMissedStatsPerfEvent())
}
