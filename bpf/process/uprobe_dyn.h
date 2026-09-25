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

// Per-thread in-flight resolution state, ie: state machine
enum resolve_stage {
	STAGE_NONE = 0,
	STAGE_MMAP_PENDING = 1,
	STAGE_DLOPEN_PENDING = 2,
	STAGE_FINAL_PENDING = 3,
};

struct pending_call {
	__u32 sym_id; // which policy rule this belongs to (index to access "regs_map" above)
	__u32 stage; // enum resolve_stage
	__u64 orig_regs[8]; // saved rdi,rsi,rdx,rcx,r8,r9 (or x0-x7 on arm)
	__u64 true_return_addr;
	__u64 orig_addr;
	__u64 expected_sp;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE); // introduced in 5.11
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int); // thread-scoped so that each thread in a process has its own pending call lookup entry
	__type(value, struct pending_call);
} pending_calls SEC(".maps");

// Computed addresses (already libc_base shifted) for mmap and dlopen
struct libc_addrs {
	__u64 mmap_addr;
	__u64 dlopen_addr;
};

// Each traced process has its own libc base address (because of ASLR)
// and thus its own mmap and dlopen addresses.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1); // will be resized by agent when needed
	__type(key, __u32); // tgid (processs-scoped: each traced process has its own cache for mmap and dlopen addresses)
	__type(value, struct libc_addrs);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} libc_addrs_map SEC(".maps");

// Resolved symbol cache, scoped per-process (not per-thread!)
struct cache_key {
	__u32 tgid;
	__u32 sym_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1); // will be resized by agent when needed
	__type(key, struct cache_key); // cached address is unique for each <process, symbol> tuple
	__type(value, __u64); // resolved address of my_new_sym
	__uint(map_flags, BPF_F_NO_PREALLOC);
} resolved_cache SEC(".maps");

FUNC_INLINE void skip_flow(__u32 sym_id, __u32 tgid, struct task_struct *task)
{
	__u64 resolved = 0;
	struct cache_key ckey = { .tgid = tgid, .sym_id = sym_id };

	task_storage_delete(&pending_calls, task);
	with_errmetrics(map_update_elem, &resolved_cache, &ckey, &resolved, BPF_ANY);
	DEBUG_SO("dynamic SO flow will be skipped for sym_id: %d tgid: %lu", sym_id, tgid);
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

FUNC_INLINE int
uprobe_dyn_state_machine(struct pt_regs *ctx, struct uprobe_regs *regs, __u32 sym_id)
{
	static const char libc[SONAME_MAX] = "libc.so.6";
	__u64 pid_tgid = get_current_pid_tgid();
	struct task_struct *task = (struct task_struct *)get_current_task_btf();
	__u32 tgid = pid_tgid >> 32;
	struct cache_key ckey = { .tgid = tgid, .sym_id = sym_id };
	__u64 *cached;
	__u64 base;
	struct libc_addrs *cached_addrs;
	struct pending_call *pending_c;

	cached = map_lookup_elem(&resolved_cache, &ckey);
	if (cached) {
		if (*cached != 0) {
			DEBUG_SO("found cached address for sym %d: 0x%lx", sym_id, *cached);
			// Found a cached entry, we just need to jump.
			jump_to(ctx, *cached);
		} else {
			DEBUG_SO("flow not working, skip.");
		}
		return 0;
	}

	DEBUG_SO("symbol %d non found in cache, try to load it", sym_id);

	pending_c = task_storage_get(&pending_calls, task, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!pending_c || pending_c->stage != STAGE_NONE)
		return 0; // either failed to get task-storage or already resolving on this thread

	cached_addrs = map_lookup_elem(&libc_addrs_map, &tgid);
	if (!cached_addrs) {
		struct libc_addrs addrs = {};

		// Still non-cached for the process, compute mmap and dlopen addrs and cache them
		base = find_library_base(task, libc);
		if (base == 0) {
			DEBUG_SO("no libc base addr for %d!", tgid);
			// find_library_base() loop failed to find a libc for the binary;
			// Skip flow for the binary.
			skip_flow(sym_id, tgid, task);
			return 0;
		}
		// Update mmap and dlopen addresses by adding libc_base
		DEBUG_SO("libc base addr for %d: 0x%lx", tgid, base);
		addrs.mmap_addr = regs->mmap_addr + base;
		addrs.dlopen_addr = regs->dlopen_addr + base;
		map_update_elem(&libc_addrs_map, &tgid, &addrs, BPF_ANY);
		cached_addrs = &addrs;
	}

	pending_c->sym_id = sym_id;
	pending_c->stage = STAGE_MMAP_PENDING;
	store_orig_regs(ctx, pending_c);

	jump_to_mmap(ctx, cached_addrs->mmap_addr);
	DEBUG_SO("JUMPING to mmap!");
	return 0;
}

SEC(OFFLOAD)
int handle_mmap_ret(struct pt_regs *ctx)
{
	__u64 pid_tgid = get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;
	struct task_struct *task = (struct task_struct *)get_current_task_btf();
	struct pending_call *pending_c;
	__u64 scratch;
	struct uprobe_regs *regs;
	struct libc_addrs *addrs;
	__u32 sopath_len;

	pending_c = task_storage_get(&pending_calls, task, NULL, 0);
	// 3 reject cases:
	// * called from a process that is not being traced
	// * return's stack depth doesn't match what we expect from our redirected call
	//   eg: a signal handler unrelated mmap call on this same thread
	//   would almost certainly be at a different stack depth due to
	//   the signal frame itself.
	// * wrong stage: the process called dlopen but from eg: a signal handler in between the calls,
	//   before uprobe_dyn_state_machine set STAGE_MMAP_PENDING.
	// Last 2 checks are mostly strengthening themselves.
	if (!pending_c || PT_REGS_SP(ctx) != pending_c->expected_sp || pending_c->stage != STAGE_MMAP_PENDING)
		return 0;

	// Store current ip as final return address for last chained call
	store_ret_addr(ctx, pending_c);

	scratch = PT_REGS_RC(ctx);
	if ((long)scratch < 0) {
		// mmap() failed.
		revert_ctx(ctx, pending_c, tgid, task);
		return 0;
	}

	regs = map_lookup_elem(&regs_map, &pending_c->sym_id);
	addrs = map_lookup_elem(&libc_addrs_map, &tgid);
	if (!regs || !addrs) {
		revert_ctx(ctx, pending_c, tgid, task);
		return 0;
	}

	sopath_len = regs->sopath_len;
	if (sopath_len == 0) {
		revert_ctx(ctx, pending_c, tgid, task);
		return 0;
	}
	sopath_len &= (SOPATH_MAX - 1);
	if (sopath_len == 0) {
		revert_ctx(ctx, pending_c, tgid, task);
		return 0;
	}

	with_errmetrics(probe_write_user, (void *)scratch, regs->sopath, sopath_len);
	pending_c->stage = STAGE_DLOPEN_PENDING;
	push_fake_frame(ctx, pending_c);

	jump_to_dlopen(ctx, scratch, addrs->dlopen_addr);
	DEBUG_SO("JUMPING to dlopen '%s'!", regs->sopath);
	return 0;
}

SEC(OFFLOAD)
int handle_dlopen_ret(struct pt_regs *ctx)
{
	__u64 pid_tgid = get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;
	struct task_struct *task = (struct task_struct *)get_current_task_btf();
	struct uprobe_regs *regs;
	__u64 handle;
	struct pending_call *pending_c;
	__u64 base;
	__u64 resolved;
	struct cache_key ckey = { .tgid = tgid };

	pending_c = task_storage_get(&pending_calls, task, NULL, 0);
	// 3 reject cases:
	// * called from a process that is not being traced
	// * return's stack depth doesn't match what we expect from our redirected call
	//   eg: a signal handler unrelated mmap call on this same thread
	//   would almost certainly be at a different stack depth due to
	//   the signal frame itself.
	// * wrong stage: the process called dlopen but from eg: a signal handler in between the calls,
	//   before the mmap retprobe set STAGE_DLOPEN_PENDING.
	// Last 2 checks are mostly strengthening themselves.
	if (!pending_c || PT_REGS_SP(ctx) != pending_c->expected_sp || pending_c->stage != STAGE_DLOPEN_PENDING)
		return 0;

	DEBUG_SO("dlopen_ret handle=%llx", PT_REGS_RC(ctx));

	handle = PT_REGS_RC(ctx);
	if (handle == 0) {
		// dlopen() failed.
		revert_ctx(ctx, pending_c, tgid, task);
		return 0;
	}

	regs = map_lookup_elem(&regs_map, &pending_c->sym_id);
	if (!regs) {
		revert_ctx(ctx, pending_c, tgid, task);
		return 0;
	}

	base = find_library_base(task, regs->soname);
	if (!base) {
		DEBUG_SO("no library base addr for %d!", tgid);
		revert_ctx(ctx, pending_c, tgid, task);
		return 0;
	}

	pending_c->stage = STAGE_FINAL_PENDING;

	resolved = base + regs->sym_addr;

	// Cache for every thread in this process from now on.
	ckey.sym_id = pending_c->sym_id;
	with_errmetrics(map_update_elem, &resolved_cache, &ckey, &resolved, BPF_ANY);

	// Restore the ORIGINAL arguments the real caller intended for my_sym.
	restore_orig_regs(ctx, pending_c);
	// Rebuild the ORIGINAL call frame, not a throwaway placeholder.
	push_fake_frame(ctx, pending_c);

	// finally jump into new symbol
	jump_to(ctx, resolved);
	task_storage_delete(&pending_calls, task);

	DEBUG_SO("JUMPING to final symbol, cached address: 0x%lx", resolved);
	return 0;
}

#endif /* __UPROBE_DYN_H__ */
