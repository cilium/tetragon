// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package config

import (
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/option"
)

// ExecObj returns the exec object based on the kernel version
func ExecObj() string {
	if EnableRhel7Progs() {
		return "bpf_execve_event_v310.o"
	} else if EnableV612Progs() {
		return "bpf_execve_event_v612.o"
	} else if EnableV61Progs() {
		return "bpf_execve_event_v61.o"
	} else if kernels.MinKernelVersion("5.11") {
		return "bpf_execve_event_v511.o"
	} else if EnableLargeProgs() {
		return "bpf_execve_event_v53.o"
	}
	return "bpf_execve_event.o"
}

func ExecUpdateObj() string {
	if kernels.MinKernelVersion("6.12") {
		return "bpf_execve_map_update_v612.o"
	} else if kernels.MinKernelVersion("5.11") {
		return "bpf_execve_map_update_v511.o"
	} else if EnableLargeProgs() {
		return "bpf_execve_map_update_v53.o"
	}
	return "bpf_execve_map_update.o"
}

func ExitObj() string {
	if EnableRhel7Progs() {
		return "bpf_exit_v310.o"
	}
	return "bpf_exit.o"
}

func ForkObj() string {
	if EnableRhel7Progs() {
		return "bpf_fork_v310.o"
	}
	return "bpf_fork.o"
}

// GenericKprobeObjs returns the generic kprobe and generic retprobe objects
func GenericKprobeObjs(multi bool) (string, string) {
	if multi {
		if EnableV612Progs() {
			return "bpf_multi_kprobe_v612.o", "bpf_multi_retkprobe_v612.o"
		} else if EnableV61Progs() {
			return "bpf_multi_kprobe_v61.o", "bpf_multi_retkprobe_v61.o"
		} else if kernels.MinKernelVersion("5.11") {
			return "bpf_multi_kprobe_v511.o", "bpf_multi_retkprobe_v511.o"
		}
		return "bpf_multi_kprobe_v53.o", "bpf_multi_retkprobe_v53.o"
	}
	if EnableV612Progs() {
		return "bpf_generic_kprobe_v612.o", "bpf_generic_retkprobe_v612.o"
	} else if EnableV61Progs() {
		return "bpf_generic_kprobe_v61.o", "bpf_generic_retkprobe_v61.o"
	} else if kernels.MinKernelVersion("5.11") {
		return "bpf_generic_kprobe_v511.o", "bpf_generic_retkprobe_v511.o"
	} else if EnableLargeProgs() {
		return "bpf_generic_kprobe_v53.o", "bpf_generic_retkprobe_v53.o"
	}
	return "bpf_generic_kprobe.o", "bpf_generic_retkprobe.o"
}

func GenericUprobeObjs(multi bool) string {
	if multi {
		if EnableV612Progs() {
			return "bpf_multi_uprobe_v612.o"
		}
		return "bpf_multi_uprobe_v61.o"
	}
	if EnableV612Progs() {
		return "bpf_generic_uprobe_v612.o"
	} else if EnableV61Progs() {
		return "bpf_generic_uprobe_v61.o"
	} else if EnableLargeProgs() {
		return "bpf_generic_uprobe_v53.o"
	}
	return "bpf_generic_uprobe.o"
}

func GenericUsdtObjs(multi bool) string {
	if multi {
		if EnableV612Progs() {
			return "bpf_multi_usdt_v612.o"
		}
		return "bpf_multi_usdt_v61.o"
	}
	if EnableV612Progs() {
		return "bpf_generic_usdt_v612.o"
	} else if EnableV61Progs() {
		return "bpf_generic_usdt_v61.o"
	}
	return "bpf_generic_usdt_v53.o"
}

func GenericTracepointObjs(raw bool) string {
	if raw {
		if EnableV612Progs() {
			return "bpf_generic_rawtp_v612.o"
		} else if EnableV61Progs() {
			return "bpf_generic_rawtp_v61.o"
		} else if kernels.MinKernelVersion("5.11") {
			return "bpf_generic_rawtp_v511.o"
		} else if EnableLargeProgs() {
			return "bpf_generic_rawtp_v53.o"
		}
		return "bpf_generic_rawtp.o"
	}
	if EnableV612Progs() {
		return "bpf_generic_tracepoint_v612.o"
	} else if EnableV61Progs() {
		return "bpf_generic_tracepoint_v61.o"
	} else if kernels.MinKernelVersion("5.11") {
		return "bpf_generic_tracepoint_v511.o"
	} else if EnableLargeProgs() {
		return "bpf_generic_tracepoint_v53.o"
	}
	return "bpf_generic_tracepoint.o"
}

func GenericLsmObjs() (string, string) {
	if EnableV612Progs() {
		return "bpf_generic_lsm_core_v612.o", "bpf_generic_lsm_output_v612.o"
	} else if EnableV61Progs() {
		return "bpf_generic_lsm_core_v61.o", "bpf_generic_lsm_output_v61.o"
	} else if kernels.MinKernelVersion("5.11") {
		return "bpf_generic_lsm_core_v511.o", "bpf_generic_lsm_output_v511.o"
	}
	return "bpf_generic_lsm_core.o", "bpf_generic_lsm_output.o"
}

func EnableRhel7Progs() bool {
	kernelVer, _, _ := kernels.GetKernelVersion(option.Config.KernelVersion, option.Config.ProcFS)
	return (int64(kernelVer) < kernels.KernelStringToNumeric("3.11.0"))
}

func EnableV61Progs() bool {
	if option.Config.ForceSmallProgs {
		return false
	}
	kernelVer, _, _ := kernels.GetKernelVersion(option.Config.KernelVersion, option.Config.ProcFS)
	return (int64(kernelVer) >= kernels.KernelStringToNumeric("6.1.0"))
}

func EnableV612Progs() bool {
	if option.Config.ForceSmallProgs {
		return false
	}
	kernelVer, _, _ := kernels.GetKernelVersion(option.Config.KernelVersion, option.Config.ProcFS)
	return (int64(kernelVer) >= kernels.KernelStringToNumeric("6.12.0"))
}

func EnableLargeProgs() bool {
	if option.Config.ForceSmallProgs {
		return false
	}
	if option.Config.ForceLargeProgs {
		return true
	}
	return bpf.HasProgramLargeSize() && bpf.HasSignalHelper()
}
