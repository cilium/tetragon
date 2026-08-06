// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __UPROBE_DYN_H__
#define __UPROBE_DYN_H__

#if defined(GENERIC_UPROBE)

// TODO: all the code here is amd64 only;
// port to arm64 too

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
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
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
	__u32 sym_id; // which policy rule this belongs to
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
	__type(key, __u64); // pid_tgid (thread-scoped)
	__type(value, struct pending_call);
} pending_calls SEC(".maps");

// --- Resolved symbol cache, scoped per-process (not per-thread!) ---
struct cache_key {
	__u32 tgid;
	__u32 sym_id;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024); // TODO: make it customizable from options?
	__type(key, struct cache_key);
	__type(value, __u64); // resolved address of my_new_sym
} resolved_cache SEC(".maps");

// Must match Go's `LibcAddrs` struct exactly: same field order, same
// widths, no implicit padding surprises. Go's ebpf.Map serializes the
// struct via binary.Write (or cilium/ebpf's built-in marshaling), which
// respects the struct's natural Go alignment — for three consecutive
// uint64s, that's already 8-byte aligned with zero padding, so a
// straightforward __u64 x3 mirrors it safely. Still worth double
// checking with `unsafe.Sizeof` on the Go side if you add fields later.
struct libc_addrs {
	__u64 mmap_addr;
	__u64 dlopen_addr;
	__u64 dlsym_addr;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024); // TODO: make it customizable from options?
	__type(key, __u32); // tgid
	__type(value, struct libc_addrs);
} libc_base_addrs_map SEC(".maps");

FUNC_INLINE struct libc_addrs *get_libc_addrs(__u32 tgid)
{
	struct libc_addrs *addrs = map_lookup_elem(&libc_base_addrs_map, &tgid);
	return addrs; // NULL if Go side hasn't populated it yet (race) or
		// this is a static binary with no libc mapping.
}

FUNC_INLINE void push_fake_frame(struct pt_regs *ctx)
{
	__u64 dummy = 0;
	ctx->sp -= 8;
	probe_write_user((void *)ctx->sp, &dummy, sizeof(dummy));
}

FUNC_INLINE void revert_ctx(struct pt_regs *ctx, struct pending_call *pc, __u64 pid_tgid)
{
	ctx->di = pc->orig_regs[0];
	ctx->si = pc->orig_regs[1];
	ctx->dx = pc->orig_regs[2];
	ctx->cx = pc->orig_regs[3];
	ctx->r8 = pc->orig_regs[4];
	ctx->r9 = pc->orig_regs[5];

	// Rebuild the call frame — required because at least one real `ret`
	// (mmap's, dlopen's, or dlsym's) has already consumed the original
	// return address from the stack by the time we get here.
	ctx->sp -= 8;
	probe_write_user((void *)ctx->sp, &pc->true_return_addr, sizeof(__u64));

	ctx->ip = pc->orig_addr;
	map_delete_elem(&pending_calls, &pid_tgid);

	// Signal that the flow is not working, and skip next time.
	__u32 tgid = pid_tgid >> 32;
	__u64 resolved = 0;
	struct cache_key ckey = { .tgid = tgid, .sym_id = pc->sym_id };
	map_update_elem(&resolved_cache, &ckey, &resolved, BPF_ANY);
}

FUNC_INLINE int
uprobe_dyn_state_machine(struct pt_regs *ctx, __u32 sym_id)
{
	__u64 pid_tgid = get_current_pid_tgid();
	__u32 tgid = pid_tgid >> 32;
	struct cache_key ckey = { .tgid = tgid, .sym_id = sym_id };

	bpf_printk("state machine init!");

	__u64 *cached = map_lookup_elem(&resolved_cache, &ckey);
	if (cached) {
		if (*cached != 0) {
			bpf_printk("cached!");
			// Found a cached entry, we just need to jump.
			ctx->ip = *cached;
		} else {
			bpf_printk("flow not working, skip.");
		}
		return 0;
	}

	bpf_printk("non cached!");

	if (map_lookup_elem(&pending_calls, &pid_tgid)) {
		return 0; // already resolving on this thread
	}

	bpf_printk("non pending calls!");

	struct libc_addrs *addrs = get_libc_addrs(tgid);
	if (!addrs) {
		bpf_printk("no addrs for %d!", tgid);
		// Either the Go-side exec hook hasn't populated this tgid yet
		// (early-startup race), or this is a static binary with no
		// libc mapping. Either way: don't override, let the real
		// my_sym execute untouched for this call.
		return 0;
	}

	struct pending_call pc = {};
	pc.sym_id = sym_id;
	pc.stage = STAGE_MMAP_PENDING;
	pc.orig_regs[0] = ctx->di;
	pc.orig_regs[1] = ctx->si;
	pc.orig_regs[2] = ctx->dx;
	pc.orig_regs[3] = ctx->cx;
	pc.orig_regs[4] = ctx->r8;
	pc.orig_regs[5] = ctx->r9;
	pc.orig_addr = ctx->ip;
	map_update_elem(&pending_calls, &pid_tgid, &pc, BPF_ANY);

	ctx->di = 0;
	ctx->si = 4096;
	ctx->dx = PROT_READ | PROT_WRITE;
	ctx->cx = MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE;
	ctx->r8 = -1;
	ctx->r9 = 0;
	ctx->ip = addrs->mmap_addr;

	bpf_printk("JUMPING to mmap!");

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
	pc->true_return_addr = ctx->ip;

	bpf_printk("mmap_ret pending!");

	__u64 scratch = PT_REGS_RC(ctx);
	if ((long)scratch < 0) {
		revert_ctx(ctx, pc, pid_tgid);
		return 0;
	}
	pc->scratch_addr = scratch;

	bpf_printk("mmap_ret scratch!");

	struct uprobe_regs *regs = map_lookup_elem(&regs_map, &pc->sym_id);
	struct libc_addrs *addrs = get_libc_addrs(tgid);
	if (!regs || !addrs) {
		revert_ctx(ctx, pc, pid_tgid);
		return 0;
	}

	bpf_printk("mmap_ret regs, addrs!");

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

	bpf_printk("mmap_ret sopath %d, %s!", sopath_len, regs->sopath);

	long ret = probe_write_user((void *)scratch, regs->sopath, sopath_len);

	long ret2 = probe_write_user((void *)(scratch + 128), regs->symbol, symbol_len);

	bpf_printk("mmap_ret probe_write_user %lld %lld!", ret, ret2);

	pc->stage = STAGE_DLOPEN_PENDING;

	push_fake_frame(ctx);

	ctx->di = scratch;
	ctx->si = RTLD_NOW;
	ctx->ip = addrs->dlopen_addr;

	bpf_printk("JUMPING to dlopen!");

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

	bpf_printk("dlopen_ret OURS, handle=%llx", PT_REGS_RC(ctx));

	__u64 handle = PT_REGS_RC(ctx);
	if (handle == 0) {
		revert_ctx(ctx, pc, pid_tgid);
		return 0;
	}

	bpf_printk("dlopen_ret handle!");

	pc->dlopen_handle = handle;
	pc->stage = STAGE_DLSYM_PENDING;

	struct libc_addrs *addrs = get_libc_addrs(tgid);
	if (!addrs) {
		revert_ctx(ctx, pc, pid_tgid);
		return 0;
	}

	bpf_printk("dlopen_ret addrs!");

	push_fake_frame(ctx);
	ctx->di = handle;
	ctx->si = pc->scratch_addr + 128;
	ctx->ip = addrs->dlsym_addr;

	bpf_printk("JUMPING to dlsym!");

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
	ctx->di = pc->orig_regs[0];
	ctx->si = pc->orig_regs[1];
	ctx->dx = pc->orig_regs[2];
	ctx->cx = pc->orig_regs[3];
	ctx->r8 = pc->orig_regs[4];
	ctx->r9 = pc->orig_regs[5];

	// Rebuild the ORIGINAL call frame, not a throwaway placeholder.
	push_fake_frame(ctx);
	probe_write_user((void *)ctx->sp, &pc->true_return_addr, sizeof(__u64));

	ctx->ip = resolved; // finally jump into new symbol

	map_delete_elem(&pending_calls, &pid_tgid);

	bpf_printk("JUMPING to final symbol!");

	return 0;
}

#endif /* GENERIC_UPROBE */
#endif /* __UPROBE_DYN_H__ */
