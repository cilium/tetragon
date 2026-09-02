// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __UPROBE_DYN_H__
#define __UPROBE_DYN_H__

#if defined(GENERIC_UPROBE)

#define DEBUG_SO(__fmt, ...) DEBUG_AREA(BPF_AREA_UPROBE_SO, __fmt, ##__VA_ARGS__)

#define PROT_READ  0x1
#define PROT_WRITE 0x2

#define MAP_PRIVATE   0x02
#define MAP_ANONYMOUS 0x20
#define MAP_POPULATE  0x008000

#define RTLD_NOW 0x00002

#define SOPATH_MAX 128
#define SYMBOL_MAX 64

struct reg_assignment {
	__u8 type;
	__u8 pad1;
	__u16 src;
	__u16 dst;
	__u8 src_size;
	__u8 dst_size;
	__u64 off;
};

#define REGS_MAX 18

struct uprobe_regs {
	struct reg_assignment ass[REGS_MAX];
	u32 cnt;
	u32 pad;
	char sopath[SOPATH_MAX]; // e.g. "/opt/safeguards/libsafemalloc.so"
	char symbol[SYMBOL_MAX]; // e.g. "my_new_sym"
	__u32 sopath_len;
	__u32 symbol_len;
	__u64 mmap_addr; // mmap address without accounting for libc base address
	__u64 dlopen_addr; // mmap address without accounting for libc base address
	__u64 dlsym_addr; // mmap address without accounting for libc base address
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32); // sym_id, based upon UprobeID and selector idx (see UprobeRegsMapID())
	__type(value, struct uprobe_regs);
} regs_map SEC(".maps");

// --- Per-thread in-flight resolution state (the actual "state machine") ---
enum resolve_stage {
	STAGE_NONE = 0,
	STAGE_MMAP_PENDING = 1,
	STAGE_DLOPEN_PENDING = 2,
	STAGE_DLSYM_PENDING = 3,
};

struct pending_call {
	__u32 sym_id; // which policy rule this belongs to (index to access "regs_map" above)
	__u32 stage; // enum resolve_stage
	__u64 orig_regs[6]; // saved rdi,rsi,rdx,rcx,r8,r9 from my_sym entry
	__u64 scratch_addr; // page returned by our mmap hijack
	__u64 dlopen_handle; // returned by dlopen, needed for dlsym call
	__u64 true_return_addr;
	__u64 orig_addr;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024); // TODO: make it customizable from options?
	__type(key, __u64); // pid_tgid (thread-scoped so that each thread in a process has its own pending call lookup entry)
	__type(value, struct pending_call);
} pending_calls SEC(".maps");

// Computed addresses (already libc_base shifted) for mmap, dlopen and dlsym
struct libc_addrs {
	__u64 mmap_addr;
	__u64 dlopen_addr;
	__u64 dlsym_addr;
};

// Each traced process has its own libc base address (because of ASLR)
// and thus its own mmap, dlopen and dlsym addresses.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024); // TODO: make it customizable from options?
	__type(key, __u32); // tgid (processs-scoped: each traced process has its own cache for mmap,dlopen and dlsym addresses)
	__type(value, struct libc_addrs);
} libc_addrs_map SEC(".maps");

// Resolved symbol cache, scoped per-process (not per-thread!)
struct cache_key {
	__u32 tgid;
	__u32 sym_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024); // TODO: make it customizable from options?
	__type(key, struct cache_key); // cached address is unique for each <process, symbol> tuple
	__type(value, __u64); // resolved address of my_new_sym
} resolved_cache SEC(".maps");

FUNC_INLINE void push_fake_frame(struct pt_regs *ctx)
{
	__u64 dummy = 0;
	PT_REGS_SP(ctx) -= 8;
	probe_write_user((void *)PT_REGS_SP(ctx), &dummy, sizeof(dummy));
}

FUNC_INLINE void skip_flow(__u32 sym_id, __u64 pid_tgid)
{
	__u32 tgid = pid_tgid >> 32;
	__u64 resolved = 0;
	struct cache_key ckey = { .tgid = tgid, .sym_id = sym_id };
	map_update_elem(&resolved_cache, &ckey, &resolved, BPF_ANY);
	DEBUG_SO("dynamic SO flow will be skipped for sym_id: %d tgid: %lu", sym_id, tgid);
}

FUNC_INLINE void revert_ctx(struct pt_regs *ctx, struct pending_call *pc, __u64 pid_tgid)
{
	PT_REGS_PARM1(ctx) = pc->orig_regs[0];
	PT_REGS_PARM2(ctx) = pc->orig_regs[1];
	PT_REGS_PARM3(ctx) = pc->orig_regs[2];
	PT_REGS_PARM4(ctx) = pc->orig_regs[3];
	PT_REGS_PARM5(ctx) = pc->orig_regs[4];
	PT_REGS_PARM6(ctx) = pc->orig_regs[5];

	// Rebuild the call frame — required because at least one real `ret`
	// (mmap's, dlopen's, or dlsym's) has already consumed the original
	// return address from the stack by the time we get here.
	PT_REGS_SP(ctx) -= 8;
	probe_write_user((void *)PT_REGS_SP(ctx), &pc->true_return_addr, sizeof(__u64));

	PT_REGS_IP(ctx) = pc->orig_addr;
	map_delete_elem(&pending_calls, &pid_tgid);

	// Signal that the flow is not working, and skip next time.
	skip_flow(pc->sym_id, pid_tgid);
}

#define LIBC_NAME "libc.so.6"

FUNC_INLINE bool name_matches(const char *name, int len)
{
	// crude suffix check for "libc.so.6" or similar — adjust as needed
	// for musl ("libc.musl-x86_64.so.1") or versioned glibc paths.
	const char target[] = LIBC_NAME;
	if (len < (int)sizeof(target) - 1)
		return false;
	for (int i = 0; i < (int)sizeof(target) - 1; i++) {
		if (name[len - (sizeof(target) - 1) + i] != target[i])
			return false;
	}
	return true;
}

FUNC_INLINE __u64 find_libc_base()
{
	struct vm_area_struct *vma;
	struct task_struct *task = (struct task_struct *)get_current_task_btf();
	if (!task)
		return 0;
	__u64 min_start = 0;
	bool found = false;
	bpf_for_each(task_vma, vma, task, 0)
	{
		struct dentry *dentry = BPF_CORE_READ(vma, vm_file, f_path.dentry);
		if (dentry == NULL) {
			continue;
		}

		char name[32];
		long n = probe_read_kernel_str(name, sizeof(name),
					       BPF_CORE_READ(dentry, d_name.name));
		if (n <= 0)
			continue;

		if (!name_matches(name, n - 1))
			continue;

		__u64 vm_start = BPF_CORE_READ(vma, vm_start);
		if (!found || vm_start < min_start) {
			min_start = vm_start;
			found = true;
		}
	}

	return found ? min_start : 0;
}

FUNC_INLINE int
uprobe_dyn_state_machine(struct pt_regs *ctx, struct uprobe_regs *regs, __u32 sym_id)
{
	__u64 pid_tgid = get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;
	struct cache_key ckey = { .tgid = tgid, .sym_id = sym_id };

	__u64 *cached = map_lookup_elem(&resolved_cache, &ckey);
	if (cached) {
		if (*cached != 0) {
			DEBUG_SO("found cached address for sym %d: 0x%lx", sym_id, *cached);
			// Found a cached entry, we just need to jump.
			PT_REGS_IP(ctx) = *cached;
		} else {
			DEBUG_SO("flow not working, skip.");
		}
		return 0;
	}

	DEBUG_SO("symbol %d non found in cache, try to load it", sym_id);

	if (map_lookup_elem(&pending_calls, &pid_tgid)) {
		return 0; // already resolving on this thread
	}

	__u64 libc_base = find_libc_base();
	if (libc_base == 0) {
		DEBUG_SO("no libc base addr for %d!", tgid);
		// find_libc_base() loop failed to find a libc for the binary;
		// Skip flow for the binary.
		skip_flow(sym_id, pid_tgid);
		return 0;
	}
	// Update mmap, dlopen and dlsym addresses by adding libc_base
	DEBUG_SO("libc base addr for %d: 0x%lx", tgid, libc_base);
	struct libc_addrs addrs = {};
	addrs.mmap_addr = regs->mmap_addr + libc_base;
	addrs.dlopen_addr = regs->dlopen_addr + libc_base;
	addrs.dlsym_addr = regs->dlsym_addr + libc_base;
	map_update_elem(&libc_addrs_map, &tgid, &addrs, BPF_ANY);

	struct pending_call pc = {};
	pc.sym_id = sym_id;
	pc.stage = STAGE_MMAP_PENDING;
	pc.orig_regs[0] = PT_REGS_PARM1(ctx);
	pc.orig_regs[1] = PT_REGS_PARM2(ctx);
	pc.orig_regs[2] = PT_REGS_PARM3(ctx);
	pc.orig_regs[3] = PT_REGS_PARM4(ctx);
	pc.orig_regs[4] = PT_REGS_PARM5(ctx);
	pc.orig_regs[5] = PT_REGS_PARM6(ctx);
	pc.orig_addr = PT_REGS_IP(ctx);
	map_update_elem(&pending_calls, &pid_tgid, &pc, BPF_ANY);

	PT_REGS_PARM1(ctx) = 0;
	PT_REGS_PARM2(ctx) = 4096;
	PT_REGS_PARM3(ctx) = PROT_READ | PROT_WRITE;
	PT_REGS_PARM4(ctx) = MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE;
	PT_REGS_PARM5(ctx) = -1;
	PT_REGS_PARM6(ctx) = 0;
	PT_REGS_IP(ctx) = addrs.mmap_addr;

	DEBUG_SO("JUMPING to mmap!");

	return 0;
}

SEC("uretprobe/mmap")
int handle_mmap_ret(struct pt_regs *ctx)
{
	__u64 pid_tgid = get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;

	struct pending_call *pc = map_lookup_elem(&pending_calls, &pid_tgid);
	if (!pc || pc->stage != STAGE_MMAP_PENDING)
		return 0;

	// Store current ip as final return address for last chained call
	pc->true_return_addr = PT_REGS_IP(ctx);

	__u64 scratch = PT_REGS_RC(ctx);
	if ((long)scratch < 0) {
		revert_ctx(ctx, pc, pid_tgid);
		return 0;
	}
	pc->scratch_addr = scratch;

	struct uprobe_regs *regs = map_lookup_elem(&regs_map, &pc->sym_id);
	struct libc_addrs *addrs = map_lookup_elem(&libc_addrs_map, &tgid);
	if (!regs || !addrs) {
		revert_ctx(ctx, pc, pid_tgid);
		return 0;
	}

	__u32 sopath_len = regs->sopath_len;
	__u32 symbol_len = regs->symbol_len;
	if (sopath_len == 0 || symbol_len == 0) {
		revert_ctx(ctx, pc, pid_tgid);
		return 0;
	}
	// Hard clamp — guarantees compile-time-provable upper bound
	sopath_len &= (SOPATH_MAX - 1);
	symbol_len &= (SYMBOL_MAX - 1);
	// Re-check for zero AFTER masking, since masking could reduce a
	// nonzero value down to zero (e.g. sopath_len == 128 -> 128 & 127 == 0)
	if (sopath_len == 0 || symbol_len == 0) {
		revert_ctx(ctx, pc, pid_tgid);
		return 0;
	}

	probe_write_user((void *)scratch, regs->sopath, sopath_len);
	probe_write_user((void *)(scratch + 128), regs->symbol, symbol_len);

	pc->stage = STAGE_DLOPEN_PENDING;

	push_fake_frame(ctx);

	PT_REGS_PARM1(ctx) = scratch;
	PT_REGS_PARM2(ctx) = RTLD_NOW;
	PT_REGS_IP(ctx) = addrs->dlopen_addr;

	DEBUG_SO("JUMPING to dlopen '%s'!", regs->sopath);

	return 0;
}

SEC("uretprobe/dlopen")
int handle_dlopen_ret(struct pt_regs *ctx)
{
	__u64 pid_tgid = get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;

	struct pending_call *pc = map_lookup_elem(&pending_calls, &pid_tgid);
	if (!pc || pc->stage != STAGE_DLOPEN_PENDING)
		return 0;

	DEBUG_SO("dlopen_ret handle=%llx", PT_REGS_RC(ctx));

	__u64 handle = PT_REGS_RC(ctx);
	if (handle == 0) {
		revert_ctx(ctx, pc, pid_tgid);
		return 0;
	}

	pc->dlopen_handle = handle;
	pc->stage = STAGE_DLSYM_PENDING;

	struct libc_addrs *addrs = map_lookup_elem(&libc_addrs_map, &tgid);
	if (!addrs) {
		revert_ctx(ctx, pc, pid_tgid);
		return 0;
	}

	push_fake_frame(ctx);
	PT_REGS_PARM1(ctx) = handle;
	PT_REGS_PARM2(ctx) = pc->scratch_addr + 128;
	PT_REGS_IP(ctx) = addrs->dlsym_addr;

	DEBUG_SO("JUMPING to dlsym '%s'!", (char *)(pc->scratch_addr + 128));

	return 0;
}

SEC("uretprobe/dlsym")
int handle_dlsym_ret(struct pt_regs *ctx)
{
	__u64 pid_tgid = get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;

	struct pending_call *pc = map_lookup_elem(&pending_calls, &pid_tgid);
	if (!pc || pc->stage != STAGE_DLSYM_PENDING)
		return 0;

	__u64 resolved = PT_REGS_RC(ctx);
	if (resolved == 0) {
		revert_ctx(ctx, pc, pid_tgid);
		return 0;
	}

	// Cache for every thread in this process from now on.
	struct cache_key ckey = { .tgid = tgid, .sym_id = pc->sym_id };
	map_update_elem(&resolved_cache, &ckey, &resolved, BPF_ANY);

	// Restore the ORIGINAL arguments the real caller intended for my_sym.
	PT_REGS_PARM1(ctx) = pc->orig_regs[0];
	PT_REGS_PARM2(ctx) = pc->orig_regs[1];
	PT_REGS_PARM3(ctx) = pc->orig_regs[2];
	PT_REGS_PARM4(ctx) = pc->orig_regs[3];
	PT_REGS_PARM5(ctx) = pc->orig_regs[4];
	PT_REGS_PARM6(ctx) = pc->orig_regs[5];

	// Rebuild the ORIGINAL call frame, not a throwaway placeholder.
	push_fake_frame(ctx);
	probe_write_user((void *)PT_REGS_SP(ctx), &pc->true_return_addr, sizeof(__u64));

	PT_REGS_IP(ctx) = resolved; // finally jump into new symbol

	map_delete_elem(&pending_calls, &pid_tgid);

	DEBUG_SO("JUMPING to final symbol, cached address: 0x%lx", resolved);

	return 0;
}

#endif /* GENERIC_UPROBE */
#endif /* __UPROBE_DYN_H__ */
