// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __UPROBE_DYN_H__
#define __UPROBE_DYN_H__

#include "errmetrics.h"

#define DEBUG_SO(__fmt, ...) DEBUG_AREA(BPF_AREA_UPROBE_SO, __fmt, ##__VA_ARGS__)

#ifdef __MULTI_KPROBE
#define OFFLOAD "uprobe.multi.s/generic_uprobe"
#else
#define OFFLOAD "uprobe.s/generic_uprobe"
#endif

#define PROT_READ  0x1
#define PROT_WRITE 0x2

#define MAP_PRIVATE   0x02
#define MAP_ANONYMOUS 0x20
#define MAP_POPULATE  0x008000

#define RTLD_NOW 0x00002

/*
 * To avoid concurrency issues, we uniquely resolve the symbol on each thread calling it.
 * We leverage BPF_MAP_TYPE_TASK_STORAGE for each task calling the symbol.
 */

// Per-thread in-flight resolution state, ie: state machine
enum resolve_stage {
	STAGE_NONE = 0,
	STAGE_MMAP_PENDING = 1,
	STAGE_DLOPEN_PENDING = 2,
	STAGE_RESOLVED = 3
};

// Struct to keep track of our state machine + additional per-task data.
struct pending_call {
	__u32 stage; // enum resolve_stage

	// Only used during a symbol resolution from sopath
	__u64 orig_regs[8]; // saved rdi,rsi,rdx,rcx,r8,r9 (or x0-x7 on arm)
	__u64 dispatch_addr; // my_sym's own address, used for mmap/dlopen pushes
	__u64 orig_addr; // initial addr to be restored in case of errors
	__u64 expected_sp; // used to avoid a signal handler called in the middle of our state machine
	__u64 true_return_addr; // final jump return address; only used for arm64

	// Computed addresses (already libc_base shifted) for mmap and dlopen + final cache for symbol address
	struct {
		__u64 mmap;
		__u64 dlopen;
		__u64 sym;
	} addrs;
};

// Each thread has its own state machine to resolve the symbol address
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE); // introduced in 5.11
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int); // thread-scoped
	__type(value, struct pending_call);
} tg_dyn_sm SEC(".maps");

FUNC_INLINE void skip_flow(struct pending_call *pending_c, __u64 pid_tgid, __u32 sym_id)
{
	pending_c->addrs.sym = 0;
	pending_c->stage = STAGE_RESOLVED;
	DEBUG_SO("dynamic SO flow will be skipped for sym_id: %d tid: %lu", sym_id, pid_tgid);
}

// Include after all maps and macros are declared so they are visible to the header.
#if defined(__TARGET_ARCH_x86)
#include "uprobe_dyn_x86.h"
#else
#include "uprobe_dyn_arm64.h"
#endif

FUNC_INLINE __u64 find_library_base(struct task_struct *task, const char *library)
{
	struct vm_area_struct *vma;

	if (!task)
		return 0;

	bpf_for_each(task_vma, vma, task, 0)
	{
		const unsigned char *nameptr;
		char name[SONAME_MAX] = {};
		long n;

		nameptr = BPF_CORE_READ(vma, vm_file, f_path.dentry, d_name.name);
		if (!nameptr)
			continue;

		n = probe_read_kernel_str(name, sizeof(name), nameptr);
		if (n <= 0)
			continue;

		if (memcmp(name, library, SONAME_MAX))
			continue;

		return BPF_CORE_READ(vma, vm_start);
	}

	return 0;
}

FUNC_INLINE int call_mmap(struct pt_regs *ctx, struct task_struct *task, __u64 pid_tgid, struct uprobe_regs *regs, __u32 sym_id)
{
	static const char libc[SONAME_MAX] = "libc.so.6";
	struct pending_call *pending_c;
	__u64 base;

	pending_c = task_storage_get(&tg_dyn_sm, task, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!pending_c) {
		DEBUG_SO("failed to create task storage for tid %ld sym_id %d", pid_tgid, sym_id);
		return 0; // failed to create task storage
	}

	base = find_library_base(task, libc);
	if (base == 0) {
		DEBUG_SO("no libc base addr for tid %ld!", pid_tgid);
		// find_library_base() loop failed to find a libc for the binary;
		// Skip flow for the binary.
		skip_flow(pending_c, pid_tgid, sym_id);
		return 0;
	}
	// Update mmap and dlopen addresses by adding libc_base
	DEBUG_SO("libc base addr for tid %ld: 0x%lx", pid_tgid, base);
	pending_c->addrs.mmap = regs->mmap_addr + base;
	pending_c->addrs.dlopen = regs->dlopen_addr + base;

	store_orig_regs(ctx, pending_c);

	pending_c->stage = STAGE_MMAP_PENDING;

	store_ret_addr(ctx, pending_c);
	push_fake_frame(ctx, pending_c);

	jump_to_mmap(ctx, pending_c->addrs.mmap);
	DEBUG_SO("JUMPING to mmap!");
	return 0;
}

FUNC_INLINE int call_dlopen(struct pt_regs *ctx, struct pending_call *pending_c, struct uprobe_regs *regs, __u64 pid_tgid, __u32 sym_id)
{
	__u32 sopath_len;
	__u64 scratch;

	scratch = PT_REGS_RC(ctx);
	if ((long)scratch < 0) {
		DEBUG_SO("mmap() failed for tid %ld!", pid_tgid);
		revert_ctx(ctx, pending_c, pid_tgid, sym_id);
		return 0;
	}

	sopath_len = regs->sopath_len;
	if (sopath_len == 0) {
		DEBUG_SO("empty sopath_len set for %ld, sym_id: %d!", pid_tgid, sym_id);
		revert_ctx(ctx, pending_c, pid_tgid, sym_id);
		return 0;
	}
	sopath_len &= (SOPATH_MAX - 1);
	if (sopath_len == 0) {
		DEBUG_SO("sopath_len too big for %ld, sym_id: %d: %d!", pid_tgid, sym_id, regs->sopath_len);
		revert_ctx(ctx, pending_c, pid_tgid, sym_id);
		return 0;
	}

	with_errmetrics(probe_write_user, (void *)scratch, regs->sopath, sopath_len);

	pending_c->stage = STAGE_DLOPEN_PENDING;

	store_ret_addr(ctx, pending_c);
	push_fake_frame(ctx, pending_c);

	jump_to_dlopen(ctx, scratch, pending_c->addrs.dlopen);
	DEBUG_SO("JUMPING to dlopen(%s)!", regs->sopath);
	return 0;
}

FUNC_INLINE int call_sym(struct pt_regs *ctx, struct pending_call *pending_c, struct uprobe_regs *regs, struct task_struct *task, __u64 pid_tgid, __u32 sym_id)
{
	__u64 base;

	DEBUG_SO("dlopen_ret handle=%llx", PT_REGS_RC(ctx));

	if (PT_REGS_RC(ctx) == 0) {
		DEBUG_SO("dlopen() failed for tid %ld!", pid_tgid);
		revert_ctx(ctx, pending_c, pid_tgid, sym_id);
		return 0;
	}

	base = find_library_base(task, regs->soname);
	if (!base) {
		DEBUG_SO("no library base addr for tid %ld!", pid_tgid);
		revert_ctx(ctx, pending_c, pid_tgid, sym_id);
		return 0;
	}

	// Cache for every thread in this process from now on.
	pending_c->addrs.sym = base + regs->sym_addr;

	// Restore the ORIGINAL arguments the real caller intended for my_sym.
	restore_orig_regs(ctx, pending_c);

	// finally jump into new symbol
	jump_to(ctx, pending_c->addrs.sym);

	pending_c->stage = STAGE_RESOLVED;

	DEBUG_SO("JUMPING to final symbol, cached address: 0x%lx", pending_c->addrs.sym);
	return 0;
}

FUNC_INLINE int
uprobe_dyn_state_machine(struct pt_regs *ctx, struct uprobe_regs *regs, __u32 sym_id)
{
	struct task_struct *task = (struct task_struct *)get_current_task_btf();
	__u64 pid_tgid = get_current_pid_tgid();
	struct pending_call *pending_c;

	pending_c = task_storage_get(&tg_dyn_sm, task, NULL, 0);
	if (!pending_c) {
		DEBUG_SO("starting state machine to load symbol: tid %ld, sym %d", pid_tgid, sym_id);
		// Non-existent task storage on this thread;
		// start the state machine.
		call_mmap(ctx, task, pid_tgid, regs, sym_id);
		return 0;
	}

	// On x86 per alignment reasons, every intermediate hop's
	// push_fake_frame (16-byte reservation) leaves sp at
	// expected_sp - 8 once the real callee's `ret` pops its 8
	// bytes. Restore the baseline.
	normalize_sp(ctx, pending_c);

	// Reject cases:
	// return's stack depth doesn't match what we expect from our redirected call
	// eg: a signal handler called the traced symbol on this same thread
	// would almost certainly be at a different stack depth due to
	// the signal frame itself.
	if (pending_c->stage != STAGE_RESOLVED && PT_REGS_SP(ctx) != pending_c->expected_sp)
		return 0;

	DEBUG_SO("state machine current stage for tid %ld: %d", pid_tgid, pending_c->stage);
	switch (pending_c->stage) {
	case STAGE_MMAP_PENDING:
		call_dlopen(ctx, pending_c, regs, pid_tgid, sym_id);
		break;
	case STAGE_DLOPEN_PENDING:
		call_sym(ctx, pending_c, regs, task, pid_tgid, sym_id);
		break;
	case STAGE_RESOLVED:
		if (pending_c->addrs.sym != 0) {
			DEBUG_SO("found cached address for tid %ld sym %d: 0x%lx", pid_tgid, sym_id, pending_c->addrs.sym);
			// Found a cached entry, we just need to jump.
			jump_to(ctx, pending_c->addrs.sym);
		} else {
			DEBUG_SO("flow not working for tid %ld sym %d, skip.", pid_tgid, sym_id);
		}
		break;
	}
	return 0;
}

#endif /* __UPROBE_DYN_H__ */
