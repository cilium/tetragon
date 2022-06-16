// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"

#include "hubble_msg.h"
#include "bpf_events.h"

/*
* # cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_lseek/format
* name: sys_enter_lseek
* ID: 682
* format:
*         field:unsigned short common_type;       offset:0;       size:2; signed:0;
*         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
*         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
*         field:int common_pid;   offset:4;       size:4; signed:1;
*
*         field:int __syscall_nr; offset:8;       size:4; signed:1;
*         field:unsigned int fd;  offset:16;      size:8; signed:0;
*         field:off_t offset;     offset:24;      size:8; signed:0;
*         field:unsigned int whence;      offset:32;      size:8; signed:0;
*
* print fmt: "fd: 0x%08lx, offset: 0x%08lx, whence: 0x%08lx", ((unsigned long)(REC->fd)), ((unsigned long)(REC->offset)), ((unsigned long)(REC->whence))
*/
struct sys_enter_lseek_args {
	__u16 common_type;
	__u8 common_flags;
	__u8 common_preempt_count;
	__s32 common_pid;
	__s32 __syscall_nr;
	__u64 fd;
	__u64 offset;
	__u64 whence;
};

char _license[] __attribute__((section("license"), used)) = "GPL";

__attribute__((section("tracepoint/sys_enter_lseek"), used)) int
test_lseek(struct sys_enter_lseek_args *ctx)
{
	// NB: this values should match BogusFd and  BogusWhenceVal in
	// pkg/sensrors/test
	if (ctx->fd == -1 && ctx->whence == 4729) {
		struct msg_test msg = { 0 };
		size_t size = sizeof(msg);
		msg.common.op = MSG_OP_TEST;
		msg.common.ktime = ktime_get_ns();
		msg.common.size = size;
		msg.arg0 = get_smp_processor_id();
		perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, &msg,
				  size);
	}

	return 0;
}
