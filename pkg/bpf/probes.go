// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package bpf

// probe constants
const (
	OverrideReturnProbe         = "override_return"
	BuildIDProbe                = "buildid"
	KprobeMultiProbe            = "kprobe_multi"
	UprobeMultiProbe            = "uprobe_multi"
	FmodRetProbe                = "fmodret"
	FmodRetSyscallProbe         = "fmodret_syscall"
	SignalHelperProbe           = "signal"
	LargeProgsProbe             = "large"
	LinkPinProbe                = "link_pin"
	LsmProbe                    = "lsm"
	MissedStatsKprobeMultiProbe = "missed_stats_kprobe_multi"
	MissedStatsKprobeProbe      = "missed_stats_kprobe"
	BatchUpdateProbe            = "batch_update"
	UprobeRefCtrOffsetProbe     = "uprobe_refctroff"
	AuditLoginUIDProbe          = "audit_loginuid"
	ProbeWriteUserProbe         = "probe_write_user"
	UprobeRegsChangeProbe       = "uprobe_regs_change"
	MixBPFAndTailCallsProbe     = "mix_bpf_and_tail_calls"
	Fentry                      = "fentry"
	GetFuncRet                  = "get_func_ret"
	SleepableTailCallsProbe     = "sleepable_tail_calls"
)
