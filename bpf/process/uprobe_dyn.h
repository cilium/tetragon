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

/**
 * This is the BPF implementation for the `ActionSelector.sopath` TracingPolicy feature that allows to
 * override a function call with an implementation that is loaded from a dynamic library.
 *
 * To avoid concurrency issues, we uniquely resolve the symbol on each thread hitting the uprobe via a
 * state machine kept in task storage (see `tg_dyn_sm` for the map and `struct pending_call` for the
 * value type).
 *
 * There are the following states:
 *
 * STATE_NONE: uprobe is hit first time
 *      |   - find libc's base base address in the task (see find_library_base()) so that we can find
 *      |     the dlopen and mmap addresses in the process memory.
 *      |   - setup registers/stack so that once we switch to user-space, thread calls mmap() to
 *      |     allocate memory for path argument and after mmap() we will return to the location
 *      |     of the uprobe
 *      |   - set stage to STAGE_MMAP_PENDING
 *      v
 * STAGE_MMAP_PENDING: uprobe is hit second time (after mmap)
 *      |   - setup registers/stack so that once we switch to user-space, thread calls dlopen()
 *      |     with the provided .so file and then fires back our uprobe
 *      |   - set stage to STAGE_DLOPEN_PENDING
 *      v
 * STAGE_DLOPEN_PENDING: uprobe is hit third time
 *      |   - leverage once again find_library_base() to compute symbol address from the loaded library one
 *      |   - cache the symbol for future usages
 *      |   - setup registers/stack so that once we switch to user-space, thread calls symbol
 *      |   - set stage to STAGE_RESOLVED; subsequent uprobe hook firing will immediately jump to symbol
 *      =
 */

// Per-thread in-flight resolution state, ie: state machine
enum resolve_stage {
	STAGE_NONE = 0,
	STAGE_MMAP_PENDING = 1,
	STAGE_DLOPEN_PENDING = 2,
	STAGE_RESOLVED = 3
};

// Struct to keep track of our state machine + additional per-task data.
// Extended to be able to resolve up to [MAX_SELECTORS] symbols.
// We only need data that is used by uprobe_dyn_state_machine()
// to be extended.
struct pending_call {
	__u32 stage[MAX_SELECTORS]; // enum resolve_stage
	__u32 sym_id[MAX_SELECTORS]; // regs_map key of the selector that started the symbol resolution

	// Only used during a symbol resolution from sopath
	// Saved registers that may carry values to the traced symbol:
	// * x86_64: rdi,rsi,rdx,rcx,r8,r9 (arguments), r10 (static chain)
	// * arm64: x0-x7 (arguments), x8 (indirect result location),
	//   x18 (static chain)
	// The static chain is a hidden argument used by GCC nested functions,
	// pointing to the enclosing function's frame.
	// The indirect result location is the address where a function returning
	// a struct larger than 16 bytes writes it; on x86_64 it is passed in rdi.
	__u64 orig_regs[10];
	__u64 dispatch_addr; // my_sym's own address, used for mmap/dlopen pushes
	__u64 orig_addr; // initial addr to be restored in case of errors
	__u64 expected_sp; // used to avoid a signal handler called in the middle of our state machine
	__u64 true_return_addr; // final jump return address; only used for arm64
	__u64 self_exec_id[MAX_SELECTORS]; // in case the thread execs another image, we reset the whole flow

	// Computed addresses (already libc_base shifted) for mmap and dlopen + final cache for symbol address
	struct {
		__u64 mmap;
		__u64 dlopen;
		__u64 libc_exec_id; // self_exec_id of the image mmap and dlopen were computed for
		__u64 sym[MAX_SELECTORS];
	} addrs;
};

// Each thread has its own state machine to resolve the symbol address
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE); // introduced in 5.11
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int); // thread-scoped
	__type(value, struct pending_call);
} tg_dyn_sm SEC(".maps");

FUNC_INLINE void skip_flow(struct pending_call *pending_c, __u64 pid_tgid, __u32 sym_id, __s32 idx)
{
	pending_c->addrs.sym[idx] = 0;
	pending_c->stage[idx] = STAGE_RESOLVED;
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

FUNC_INLINE int call_mmap(struct pt_regs *ctx, struct task_struct *task, __u64 pid_tgid, struct uprobe_regs *regs, __u32 sym_id, __u64 self_exec_id, __s32 idx)
{
	static const char libc[SONAME_MAX] = "libc.so.6";
	struct pending_call *pending_c;
	__u64 base;

	pending_c = task_storage_get(&tg_dyn_sm, task, NULL, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!pending_c) {
		DEBUG_SO("failed to create task storage for tid %ld sym_id %d", pid_tgid, sym_id);
		return 0; // failed to create task storage
	}

	// Only load if needed: libc base is shared by all the symbols resolved
	// by this thread, but it must be recomputed if the thread exec'd.
	// A new task storage is zeroed, and a user task self_exec_id is never 0
	// (every exec increments it), so this also covers the first resolution.
	if (pending_c->addrs.libc_exec_id != self_exec_id) {
		base = find_library_base(task, libc);
		if (base == 0) {
			DEBUG_SO("no libc base addr for tid %ld!", pid_tgid);
			// find_library_base() loop failed to find a libc for the binary;
			// Skip flow for the binary.
			skip_flow(pending_c, pid_tgid, sym_id, idx);
			return 0;
		}
		// Update mmap and dlopen addresses by adding libc_base
		DEBUG_SO("libc base addr for tid %ld: 0x%lx", pid_tgid, base);
		pending_c->addrs.mmap = regs->mmap_addr + base;
		pending_c->addrs.dlopen = regs->dlopen_addr + base;
		pending_c->addrs.libc_exec_id = self_exec_id;
	}

	store_orig_regs(ctx, pending_c);

	pending_c->self_exec_id[idx] = self_exec_id;
	pending_c->sym_id[idx] = sym_id;
	pending_c->stage[idx] = STAGE_MMAP_PENDING;

	store_ret_addr(ctx, pending_c);
	push_fake_frame(ctx, pending_c);

	jump_to_mmap(ctx, pending_c->addrs.mmap);
	DEBUG_SO("JUMPING to mmap!");
	return 0;
}

FUNC_INLINE int call_dlopen(struct pt_regs *ctx, struct pending_call *pending_c, struct uprobe_regs *regs, __u64 pid_tgid, __s32 idx)
{
	__u32 sopath_len;
	__u64 scratch;

	scratch = PT_REGS_RC(ctx);
	if ((long)scratch < 0) {
		DEBUG_SO("mmap() failed for tid %ld!", pid_tgid);
		revert_ctx(ctx, pending_c, pid_tgid, idx);
		return 0;
	}

	sopath_len = regs->sopath_len;
	if (sopath_len == 0) {
		DEBUG_SO("empty sopath_len set for %ld, sym_id: %d!", pid_tgid, pending_c->sym_id[idx]);
		revert_ctx(ctx, pending_c, pid_tgid, idx);
		return 0;
	}
	sopath_len &= (SOPATH_MAX - 1);
	if (sopath_len == 0) {
		DEBUG_SO("sopath_len too big for %ld, sym_id: %d: %d!", pid_tgid, pending_c->sym_id[idx], regs->sopath_len);
		revert_ctx(ctx, pending_c, pid_tgid, idx);
		return 0;
	}

	with_errmetrics(probe_write_user, (void *)scratch, regs->sopath, sopath_len);

	pending_c->stage[idx] = STAGE_DLOPEN_PENDING;

	store_ret_addr(ctx, pending_c);
	push_fake_frame(ctx, pending_c);

	jump_to_dlopen(ctx, scratch, pending_c->addrs.dlopen);
	DEBUG_SO("JUMPING to dlopen(%s)!", regs->sopath);
	return 0;
}

FUNC_INLINE int call_sym(struct pt_regs *ctx, struct pending_call *pending_c, struct uprobe_regs *regs, struct task_struct *task, __u64 pid_tgid, __s32 idx)
{
	__u64 base;

	DEBUG_SO("dlopen_ret handle=%llx", PT_REGS_RC(ctx));

	if (PT_REGS_RC(ctx) == 0) {
		DEBUG_SO("dlopen() failed for tid %ld!", pid_tgid);
		revert_ctx(ctx, pending_c, pid_tgid, idx);
		return 0;
	}

	base = find_library_base(task, regs->soname);
	if (!base) {
		DEBUG_SO("no library base addr for tid %ld!", pid_tgid);
		revert_ctx(ctx, pending_c, pid_tgid, idx);
		return 0;
	}

	// Cache for every thread in this process from now on.
	pending_c->addrs.sym[idx] = base + regs->sym_addr;

	// Restore the ORIGINAL arguments the real caller intended for my_sym.
	restore_orig_regs(ctx, pending_c);

	// finally jump into new symbol
	jump_to(ctx, pending_c->addrs.sym[idx]);

	pending_c->stage[idx] = STAGE_RESOLVED;

	DEBUG_SO("JUMPING to final symbol, cached address: 0x%lx", pending_c->addrs.sym[idx]);
	return 0;
}

FUNC_INLINE __s32 find_avail_pending_c_idx(struct pending_call *pending_c, __u32 sym_id)
{
	if (!pending_c)
		return 0;

	// If we find sym_id, return it
#pragma unroll
	for (int i = 0; i < MAX_SELECTORS; ++i) {
		if (pending_c->sym_id[i] == sym_id)
			return i;
	}
	// Else, find a free slot
#pragma unroll
	for (int i = 0; i < MAX_SELECTORS; ++i) {
		if (pending_c->stage[i] == STAGE_NONE)
			return i;
	}

	return -1;
}

// Returns the slot index of the resolution in progress, other than skip_idx,
// or -1 if none.
// Saved registers, return address and expected sp are shared by all the
// slots: only a single resolution can be in progress per thread.
FUNC_INLINE __s32 find_pending_idx(struct pending_call *pending_c, __s32 skip_idx)
{
#pragma unroll
	for (int i = 0; i < MAX_SELECTORS; ++i) {
		if (i == skip_idx)
			continue;
		if (pending_c->stage[i] == STAGE_MMAP_PENDING || pending_c->stage[i] == STAGE_DLOPEN_PENDING)
			return i;
	}
	return -1;
}

FUNC_INLINE int
uprobe_dyn_state_machine(struct pt_regs *ctx, struct uprobe_regs *regs, __u32 sym_id)
{
	struct task_struct *task = (struct task_struct *)get_current_task_btf();
	__u64 pid_tgid = get_current_pid_tgid();
	struct pending_call *pending_c;
	__u64 self_exec_id;
	__s32 idx;

	BPF_CORE_READ_INTO(&self_exec_id, task, self_exec_id);
	pending_c = task_storage_get(&tg_dyn_sm, task, NULL, 0);
	idx = find_avail_pending_c_idx(pending_c, sym_id);
	if (idx == -1) {
		// Should never happen, validated in userspace
		DEBUG_SO("reached limit of per-thread sopath overrides, skipping: tid %ld, sym %d, limit: %d", pid_tgid, sym_id, MAX_SELECTORS);
		return 0;
	}

	// We have different cases where we want to trigger the symbol resolution:
	// * pending_c was never allocated (ie: first time a traced symbol with override.sopath is called)
	// * we are overriding a different symbol (from another selector)
	// * the thread calls `execve` thus replacing its process image
	if (!pending_c || pending_c->stage[idx] == STAGE_NONE || pending_c->self_exec_id[idx] != self_exec_id) {
		if (pending_c && find_pending_idx(pending_c, idx) != -1) {
			// A resolution of symbol A runs real code on the same thread:
			// mmap(), dlopen(), dynamic loader, and the ctors of the library being loaded.
			// If that code calls another traced symbol B with a sopath override,
			// a nested resolution starts. Avoid that.
			// Example with overrides on malloc (A) and free (B):
			// 1. malloc is hit -> call_mmap() saves A's context and redirects into mmap()
			// 2. mmap() returns to the fake frame. A advances and redirects into dlopen()
			// 3. Inside dlopen(), the loader calls free.
			// 4. free is hit at a deeper stack; luckily enough, we know there is an in flight override;
			//    otherwise we would have trashed current resolution registers
			DEBUG_SO("another symbol resolution is in progress, skipping: tid %ld, sym %d", pid_tgid, sym_id);
			return 0;
		}
		// Non-existent task storage or slot on this thread, or the
		// task exec'd another image: (re)start the state machine.
		DEBUG_SO("starting state machine to load symbol: tid %ld, sym %d, exec_id: %ld", pid_tgid, sym_id, self_exec_id);
		call_mmap(ctx, task, pid_tgid, regs, sym_id, self_exec_id, idx);
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
	if (pending_c->stage[idx] != STAGE_RESOLVED && PT_REGS_SP(ctx) != pending_c->expected_sp)
		return 0;

	DEBUG_SO("state machine current stage for tid %ld, sym %d: %d", pid_tgid, sym_id, pending_c->stage[idx]);
	switch (pending_c->stage[idx]) {
	case STAGE_MMAP_PENDING:
		call_dlopen(ctx, pending_c, regs, pid_tgid, idx);
		break;
	case STAGE_DLOPEN_PENDING:
		call_sym(ctx, pending_c, regs, task, pid_tgid, idx);
		break;
	case STAGE_RESOLVED:
		if (pending_c->addrs.sym[idx] != 0) {
			DEBUG_SO("found cached address for tid %ld sym %d: 0x%lx", pid_tgid, sym_id, pending_c->addrs.sym[idx]);
			// Found a cached entry, we just need to jump.
			jump_to(ctx, pending_c->addrs.sym[idx]);
		} else {
			DEBUG_SO("flow not working for tid %ld sym %d, skip.", pid_tgid, sym_id);
		}
		break;
	}
	return 0;
}

// Returns true if the current thread is resolving a symbol from sopath and
// this uprobe hit is the return from the mmap() or dlopen() detour, storing in
// sym_id the regs_map key of the selector that started the resolution.
// Such hits are not calls to the traced symbol: the main program skips them,
// and the offload program continues the resolution whatever the selectors
// would match, as the registers hold the values left by mmap() and dlopen().
FUNC_INLINE bool uprobe_dyn_pending(struct pt_regs *ctx, __u32 *sym_id)
{
	struct task_struct *task = (struct task_struct *)get_current_task_btf();
	struct pending_call *pending_c;
	__s32 idx;

	pending_c = task_storage_get(&tg_dyn_sm, task, NULL, 0);
	if (!pending_c)
		return false;

	idx = find_pending_idx(pending_c, -1);
	if (idx == -1)
		return false;

	// The pending slot only tells that a resolution is in progress on this thread.
	// While it is, traced symbols can also be hit from within mmap() or dlopen()
	// (eg: malloc, library constructors) or from a signal handler. Those calls
	// run on deeper stack frames, so only the return from our detour is back at
	// expected_sp. Any other hit keeps the selector driven handling, so that its
	// own queued action is not replaced by the pending resolution.
	// Don't use normalize_sp() here, as it modifies sp.
	if (!is_expected_sp(ctx, pending_c))
		return false;

	*sym_id = pending_c->sym_id[idx];
	return true;
}

#endif /* __UPROBE_DYN_H__ */
