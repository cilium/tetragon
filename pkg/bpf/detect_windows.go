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

func HasLinkPin() bool {
	return false
}

func HasKprobeMulti() bool {
	return false
}

func HasBatchAPI() bool {
	return false
}

func DetectMixBpfAndTailCalls() bool {
	return false
}

func LogFeatures() string {
	return fmt.Sprintf("override_return: %t, buildid: %t, fmodret: %t, fmodret_syscall: %t, signal: %t, large: %t, link_pin: %t mix_bpf_and_tail_calls: %t",
		HasOverrideHelper(), HasBuildId(), HasModifyReturn(), HasModifyReturnSyscall(), HasSignalHelper(), HasProgramLargeSize(),
		HasLinkPin(), DetectMixBpfAndTailCalls())
}
