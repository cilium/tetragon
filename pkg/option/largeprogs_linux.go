// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package option

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
)

// EnableLargeProgs reports whether to load the large BPF programs. It lives
// here rather than in pkg/config so that ReadAndSetFlags can use it: the
// option package can't import pkg/config or pkg/bpf without a cycle.
func EnableLargeProgs() bool {
	if Config.ForceSmallProgs {
		return false
	}
	if Config.ForceLargeProgs {
		return true
	}
	return features.HaveLargeInstructions() == nil &&
		features.HaveProgramHelper(ebpf.Kprobe, asm.FnSendSignal) == nil
}
