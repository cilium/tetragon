// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __BASIC_H__
#define __BASIC_H__

#include "operations.h"
#include "bpf_task.h"
#include "bpf_cred.h"
#include "skb.h"
#include "sock.h"
#include "sockaddr.h"
#include "socket.h"
#include "net_device.h"
#include "../bpf_process_event.h"
#include "bpfattr.h"
#include "perfevent.h"
#include "bpfmap.h"
#include "capabilities.h"
#include "module.h"
#include "../argfilter_maps.h"
#include "../addr_lpm_maps.h"
#include "../string_maps.h"
#include "common.h"
#include "process/data_event.h"
#include "process/bpf_enforcer.h"
#include "../syscall64.h"
#include "process/ratelimit_maps.h"
#include "process/heap.h"
#include "../bpf_mbset.h"
#include "bpf_ktime.h"

/* Type IDs form API with user space generickprobe.go */
enum {
	invalid_ty = -2,
	nop_ty = -1,
	int_type = 1,
	char_buf = 2,
	char_iovec = 3,
	size_type = 4,
	skb_type = 5,
	string_type = 6,
	sock_type = 7,
	cred_type = 8,

	s64_ty = 10,
	u64_ty = 11,
	s32_ty = 12,
	u32_ty = 13,

	filename_ty = 14,
	path_ty = 15,
	file_ty = 16,
	fd_ty = 17,

	/* const_buf_type is a type for buffers with static size that is passed
	 * in the meta argument
	 */
	const_buf_type = 18,
	bpf_attr_type = 19,
	perf_event_type = 20,
	bpf_map_type = 21,
	user_namespace_type = 22,
	capability_type = 23,

	kiocb_type = 24,
	iov_iter_type = 25,

	load_module_type = 26,
	kernel_module_type = 27,

	syscall64_type = 28,

	s16_ty = 29,
	u16_ty = 30,
	s8_ty = 31,
	u8_ty = 32,

	kernel_cap_ty = 33,
	cap_inh_ty = 34,
	cap_prm_ty = 35,
	cap_eff_ty = 36,

	linux_binprm_type = 37,

	data_loc_type = 38,

	net_dev_ty = 39,

	sockaddr_type = 40,
	socket_type = 41,

	dentry_type = 42,

	bpf_prog_type = 43,
	int32_arr_type = 44,

	nop_s64_ty = -10,
	nop_u64_ty = -11,
	nop_u32_ty = -12,
	nop_s32_ty = -13,
};

enum {
	char_buf_enomem = -1,
	char_buf_pagefault = -2,
	char_buf_toolarge = -3,
	char_buf_saved_for_retprobe = -4,
};

enum {
	ACTION_POST = 0,
	ACTION_FOLLOWFD = 1,
	/* Actual SIGKILL value, but we dont want to pull headers in */
	ACTION_SIGKILL = 2,
	ACTION_UNFOLLOWFD = 3,
	ACTION_OVERRIDE = 4,
	ACTION_COPYFD = 5,
	ACTION_GETURL = 6,
	ACTION_DNSLOOKUP = 7,
	ACTION_NOPOST = 8,
	ACTION_SIGNAL = 9,
	ACTION_TRACKSOCK = 10,
	ACTION_UNTRACKSOCK = 11,
	ACTION_NOTIFY_ENFORCER = 12,
	ACTION_CLEANUP_ENFORCER_NOTIFICATION = 13,
	ACTION_SET = 14,
};

enum {
	FGS_SIGKILL = 9,
};

enum {
	TAIL_CALL_SETUP = 0,
	TAIL_CALL_PROCESS = 1,
	TAIL_CALL_FILTER = 2,
	TAIL_CALL_ARGS = 3,
	TAIL_CALL_ACTIONS = 4,
	TAIL_CALL_SEND = 5,
	TAIL_CALL_PATH = 6,
};

struct selector_action {
	__u32 actionlen;
	__u32 act[];
};

struct selector_arg_filter {
	__u32 index;
	__u32 op;
	__u32 vallen;
	__u32 type;
	__u8 value;
} __attribute__((packed));

struct selector_arg_filters {
	__u32 arglen;
	__u32 argoff[5];
} __attribute__((packed));

struct config_btf_arg {
	__u32 offset;
	__u16 is_pointer;
	__u16 is_initialized;
} __attribute__((packed));

#define USDT_ARG_TYPE_NONE	0
#define USDT_ARG_TYPE_CONST	1
#define USDT_ARG_TYPE_REG	2
#define USDT_ARG_TYPE_REG_DEREF 3
#define USDT_ARG_TYPE_SIB	4

struct config_usdt_arg {
	__u64 val_off;
	__u32 reg_off;
	__u32 reg_idx_off;
	__u8 shift;
	__u8 type;
	__u8 sig;
	__u8 scale;
	__u32 pad1;
} __attribute__((packed));

struct config_reg_arg {
	__u16 offset;
	__u8 size;
	__u8 pad;
} __attribute__((packed));

struct extract_arg_data {
	struct config_btf_arg *btf_config;
	unsigned long *arg;
};

#define MAX_BTF_ARG_DEPTH	  10
#define EVENT_CONFIG_MAX_ARG	  5
#define EVENT_CONFIG_MAX_USDT_ARG 8
#define EVENT_CONFIG_MAX_REG_ARG  8

struct event_config {
	__u32 func_id;
	__s32 arg[EVENT_CONFIG_MAX_ARG];
	__u32 arm[EVENT_CONFIG_MAX_ARG];
	__u32 off[EVENT_CONFIG_MAX_ARG];
	__s32 idx[EVENT_CONFIG_MAX_ARG];
	__u32 syscall;
	__s32 argreturncopy;
	__s32 argreturn;
	/* arg return action specifies to act on the return value; currently
	 * supported actions include: TrackSock and UntrackSock.
	 */
	__u32 argreturnaction;
	/* policy id identifies the policy of this generic hook and is used to
	 * apply policies only on certain processes. A value of 0 indicates
	 * that the hook always applies and no check will be performed.
	 */
	__u32 policy_id;
	__u32 flags;
	__u32 pad;
	struct config_btf_arg btf_arg[EVENT_CONFIG_MAX_ARG][MAX_BTF_ARG_DEPTH];
	struct config_usdt_arg usdt_arg[EVENT_CONFIG_MAX_USDT_ARG];
	struct config_reg_arg reg_arg[EVENT_CONFIG_MAX_REG_ARG];
} __attribute__((packed));

#define MAX_ARGS_SIZE	 80
#define MAX_ARGS_ENTRIES 8
#define MAX_FILTER_INT_ARGS 8
#define MAX_MATCH_VALUES 4
/* String parsing consumes instructions so this adds an additional
 * knob to tune how many instructions we should spend parsing
 * strings.
 */
#define MAX_MATCH_STRING_VALUES 2

/* Number of values allowed in matchArgs while using an "fd" or "file" arg.
 */
#ifdef __LARGE_BPF_PROG
#define MAX_MATCH_FILE_VALUES 8
#else
#define MAX_MATCH_FILE_VALUES 2
#endif

/* Number of allowed actions for selector.
 */
#define MAX_ACTIONS 3

/* Constants bounding printers if these change or buffer size changes then
 * we will need to resize. TBD would be to size these at compile time using
 * buffer size information.
 */
#ifdef __LARGE_BPF_PROG
#ifdef __V511_BPF_PROG
#define MAX_STRING (STRING_MAPS_SIZE_10 - 2)
#else
#define MAX_STRING (STRING_MAPS_SIZE_7 - 2)
#endif
#else
#define MAX_STRING (STRING_MAPS_SIZE_5 - 1)
#endif

struct msg_linux_binprm {
	char path[MAX_STRING];
} __attribute__((packed));

#ifdef __MULTI_KPROBE
FUNC_INLINE __u32 get_index(void *ctx)
{
	return (__u32)get_attach_cookie(ctx);
}
#else
#define get_index(ctx) 0
#endif

// We do one tail-call per selector, we can have up to 5 selectors.
#define MAX_SELECTORS	   5
#define MAX_SELECTORS_MASK 7

FUNC_INLINE long
filter_32ty_map(struct selector_arg_filter *filter, char *args);

FUNC_INLINE int return_error(int *s, int err)
{
	*s = err;
	return sizeof(int);
}

FUNC_INLINE char *
args_off(struct msg_generic_kprobe *e, unsigned long off)
{
	asm volatile("%[off] &= 0x3fff;\n"
		     : [off] "+r"(off));
	return e->args + off;
}

/* Error writer for use when pointer *s is lost to stack and can not
 * be recoved with known bounds. We had to push this via asm to stop
 * clang from omitting some checks and applying code motion on us.
 */
FUNC_INLINE int
return_stack_error(char *args, int orig, int err)
{
	asm volatile("%[orig] &= 0xfff;\n"
		     "r1 = *(u64 *)%[args];\n"
		     "r1 += %[orig];\n"
		     "*(u32 *)(r1 + 0) = %[err];\n"
		     : [orig] "+r"(orig), [args] "+m"(args), [err] "+r"(err)
		     :
		     : "r1");
	return sizeof(int);
}

FUNC_INLINE int
parse_iovec_array(long off, unsigned long arg, int i, unsigned long max,
		  struct msg_generic_kprobe *e)
{
	struct iovec
		iov; // limit is 1024 using a hack now. For 5.4 kernel we should loop over 1024
	char index = sizeof(struct iovec) * i;
	__u64 size;
	int err;

	err = probe_read(&iov, sizeof(iov), (struct iovec *)(arg + index));
	if (err < 0)
		return char_buf_pagefault;
	size = iov.iov_len;
	if (max && size > max)
		size = max;
	if (size > 4094)
		return char_buf_toolarge;
	asm volatile("%[size] &= 0xfff;\n"
		     : [size] "+r"(size));
	err = probe_read(args_off(e, off), size, (char *)iov.iov_base);
	if (err < 0)
		return char_buf_pagefault;
	return size;
}

// for loop can not be unrolled which is needed for 4.19 kernels :(
#define PARSE_IOVEC_ENTRY                                                \
	{                                                                \
		int c;                                                   \
		/* embedding this in the loop counter breaks verifier */ \
		if (i >= cnt)                                            \
			goto char_iovec_done;                            \
		c = parse_iovec_array(off, arg, i, max, e);              \
		if (c < 0) {                                             \
			char *args = args_off(e, off_orig);              \
			return return_stack_error(args, 0, c);           \
		}                                                        \
		size += c;                                               \
		if (max) {                                               \
			max -= c;                                        \
			if (!max)                                        \
				goto char_iovec_done;                    \
		}                                                        \
		c &= 0x7fff;                                             \
		off += c;                                                \
		i++;                                                     \
	}

// We parse a max iovec entries and any more can be detected in db
#define PARSE_IOVEC_ENTRIES       \
	{                         \
		PARSE_IOVEC_ENTRY \
		PARSE_IOVEC_ENTRY \
		PARSE_IOVEC_ENTRY \
		PARSE_IOVEC_ENTRY \
		PARSE_IOVEC_ENTRY \
		PARSE_IOVEC_ENTRY \
		PARSE_IOVEC_ENTRY \
	}

#ifdef __LARGE_BPF_PROG
#define MAX_STRING_FILTER 128
#else
#define MAX_STRING_FILTER 32
#endif

FUNC_INLINE long store_path(char *args, char *buffer, const struct path *arg,
			    int size, int flags)
{
	int *s = (int *)args;
	void *curr = &args[4];
	umode_t i_mode;

	asm volatile("%[size] &= 0xfff;\n"
		     : [size] "+r"(size));
	probe_read(curr, size, buffer);
	*s = size;
	size += 4;

	BPF_CORE_READ_INTO(&i_mode, arg, dentry, d_inode, i_mode);

	/*
	 * the format of the path is:
	 * -----------------------------------------
	 * | 4 bytes | N bytes | 4 bytes | 2 bytes |
	 * | pathlen |  path   |  flags  |   mode  |
	 * -----------------------------------------
	 * Next we set up the flags.
	 */
	*(u32 *)&args[size] = (u32)flags;
	*(u16 *)&args[size + sizeof(u32)] = (u16)i_mode;
	size += sizeof(u32) + sizeof(u16); // for the flags + i_mode

	return size;
}

FUNC_INLINE long copy_path(char *args, const struct path *arg)
{
	int size = 0, flags = 0;
	char *buffer;

	buffer = d_path_local(arg, &size, &flags);
	if (!buffer)
		return 0;

	return store_path(args, buffer, arg, size, flags);
}

FUNC_INLINE long copy_strings(char *args, char *arg, int max_size)
{
	int *s = (int *)args;
	long size;

	// probe_read_str() always nul-terminates the string.
	// So add one to the length to allow for it. This should
	// result in us honouring our max_size correctly.
	size = probe_read_str(&args[4], max_size + 1, arg);
	if (size <= 1)
		return invalid_ty;
	// Remove the nul character from end.
	size--;
	*s = size;
	// Initial 4 bytes hold string length
	return size + 4;
}

FUNC_INLINE long copy_skb(char *args, unsigned long arg)
{
	struct sk_buff *skb = (struct sk_buff *)arg;
	struct skb_type *skb_event = (struct skb_type *)args;

	/* struct values */
	probe_read(&skb_event->hash, sizeof(__u32), _(&skb->hash));
	probe_read(&skb_event->len, sizeof(__u32), _(&skb->len));
	probe_read(&skb_event->priority, sizeof(__u32), _(&skb->priority));
	probe_read(&skb_event->mark, sizeof(__u32), _(&skb->mark));

	/* socket data */
	set_event_from_skb(skb_event, skb);

	return sizeof(struct skb_type);
}

FUNC_INLINE long copy_sock(char *args, unsigned long arg)
{
	struct sock *sk = (struct sock *)arg;
	struct sk_type *sk_event = (struct sk_type *)args;

	set_event_from_sock(sk_event, sk);

	return sizeof(struct sk_type);
}

FUNC_INLINE long copy_sockaddr(char *args, unsigned long arg)
{
	struct sockaddr_in_type *sockaddr_event = (struct sockaddr_in_type *)args;
	struct sockaddr *address = (struct sockaddr *)arg;

	set_event_from_sockaddr_in(sockaddr_event, address);

	return sizeof(struct sockaddr_in_type);
}

FUNC_INLINE long copy_socket(char *args, unsigned long arg)
{
	struct socket *sock = (struct socket *)arg;
	struct sk_type *sk_event = (struct sk_type *)args;

	set_event_from_socket(sk_event, sock);

	return sizeof(struct sk_type);
}

FUNC_INLINE long copy_user_ns(char *args, unsigned long arg)
{
	struct user_namespace *ns = (struct user_namespace *)arg;
	struct msg_user_namespace *u_ns_info =
		(struct msg_user_namespace *)args;

	probe_read(&u_ns_info->level, sizeof(__s32), _(&ns->level));
	probe_read(&u_ns_info->uid, sizeof(__u32), _(&ns->owner));
	probe_read(&u_ns_info->gid, sizeof(__u32), _(&ns->group));
	probe_read(&u_ns_info->ns_inum, sizeof(__u32), _(&ns->ns.inum));

	return sizeof(struct msg_user_namespace);
}

FUNC_INLINE long copy_cred(char *args, unsigned long arg)
{
	struct user_namespace *ns;
	struct cred *cred = (struct cred *)arg;
	struct msg_cred *info = (struct msg_cred *)args;
	struct msg_capabilities *caps = &info->caps;
	struct msg_user_namespace *user_ns_info = &info->user_ns;

	probe_read(&info->uid, sizeof(__u32), _(&cred->uid));
	probe_read(&info->gid, sizeof(__u32), _(&cred->gid));
	probe_read(&info->euid, sizeof(__u32), _(&cred->euid));
	probe_read(&info->egid, sizeof(__u32), _(&cred->egid));
	probe_read(&info->suid, sizeof(__u32), _(&cred->suid));
	probe_read(&info->sgid, sizeof(__u32), _(&cred->sgid));
	probe_read(&info->fsuid, sizeof(__u32), _(&cred->fsuid));
	probe_read(&info->fsgid, sizeof(__u32), _(&cred->fsgid));
	info->pad = 0;
	probe_read(&info->securebits, sizeof(__u32), _(&cred->securebits));

	__get_caps(caps, cred);

	probe_read(&ns, sizeof(ns), _(&cred->user_ns));
	copy_user_ns((char *)user_ns_info, (unsigned long)ns);

	return sizeof(struct msg_cred);
}

FUNC_INLINE long copy_capability(char *args, unsigned long arg)
{
	int cap = (int)arg;
	struct capability_info_type *info = (struct capability_info_type *)args;

	info->pad = 0;
	info->cap = cap;

	return sizeof(struct capability_info_type);
}

FUNC_INLINE long copy_load_module(char *args, unsigned long arg)
{
	int ok;
	const char *name;
	const struct load_info *mod = (struct load_info *)arg;
	struct tg_kernel_module *info = (struct tg_kernel_module *)args;

	memset(info, 0, sizeof(struct tg_kernel_module));

	if (BPF_CORE_READ_INTO(&name, mod, name) != 0)
		return 0;

	if (probe_read_str(&info->name, TG_MODULE_NAME_LEN - 1, name) < 0)
		return 0;

	BPF_CORE_READ_INTO(&info->taints, mod, mod, taints);

	if (BPF_CORE_READ_INTO(&ok, mod, sig_ok) == 0)
		info->sig_ok = !!ok;

	return sizeof(struct tg_kernel_module);
}

FUNC_INLINE long copy_kernel_module(char *args, unsigned long arg)
{
	const struct module *mod = (struct module *)arg;
	struct tg_kernel_module *info = (struct tg_kernel_module *)args;

	memset(info, 0, sizeof(struct tg_kernel_module));

	if (probe_read_str(&info->name, TG_MODULE_NAME_LEN - 1, mod->name) < 0)
		return 0;

	BPF_CORE_READ_INTO(&info->taints, mod, taints);

	/*
	 * Todo: allow to check if module is signed here too.
	 *  the module->sig_ok is available only under CONFIG_MODULE_SIG option, so
	 *  let's not fail here, and users can check the load_info->sig_ok instead.
	 */

	return sizeof(struct tg_kernel_module);
}

#define ARGM_INDEX_MASK	  0xf
#define ARGM_RETURN_COPY  BIT(4)
#define ARGM_MAX_DATA	  BIT(5)
#define ARGM_CURRENT_TASK BIT(6)
#define ARGM_PT_REGS	  BIT(7)

FUNC_INLINE bool has_return_copy(unsigned long argm)
{
	return (argm & ARGM_RETURN_COPY) != 0;
}

FUNC_INLINE bool has_max_data(unsigned long argm)
{
	return (argm & ARGM_MAX_DATA) != 0;
}

FUNC_INLINE unsigned long get_arg_meta(int meta, struct msg_generic_kprobe *e)
{
	switch (meta & ARGM_INDEX_MASK) {
	case 1:
		return e->a0;
	case 2:
		return e->a1;
	case 3:
		return e->a2;
	case 4:
		return e->a3;
	case 5:
		return e->a4;
	}
	return 0;
}

FUNC_INLINE u16 string_padded_len(u16 len)
{
	u16 padded_len = len;

	if (len < STRING_MAPS_SIZE_5) {
		if (len % STRING_MAPS_KEY_INC_SIZE != 0)
			padded_len = ((len / STRING_MAPS_KEY_INC_SIZE) + 1) * STRING_MAPS_KEY_INC_SIZE;
		return padded_len;
	}
	if (len <= STRING_MAPS_SIZE_6 - 2)
		return STRING_MAPS_SIZE_6 - 2;
#ifdef __LARGE_BPF_PROG
#ifdef __V511_BPF_PROG
	if (len <= STRING_MAPS_SIZE_7 - 2)
		return STRING_MAPS_SIZE_7 - 2;
	if (len <= STRING_MAPS_SIZE_8 - 2)
		return STRING_MAPS_SIZE_8 - 2;
	if (len <= STRING_MAPS_SIZE_9 - 2)
		return STRING_MAPS_SIZE_9 - 2;
	return STRING_MAPS_SIZE_10 - 2;
#else
	return STRING_MAPS_SIZE_7 - 2;
#endif
#else
	return STRING_MAPS_SIZE_5 - 1;
#endif
}

FUNC_INLINE int string_map_index(u16 padded_len)
{
	if (padded_len < STRING_MAPS_SIZE_5)
		return (padded_len / STRING_MAPS_KEY_INC_SIZE) - 1;

#ifdef __LARGE_BPF_PROG
#ifdef __V511_BPF_PROG
	switch (padded_len) {
	case STRING_MAPS_SIZE_6 - 2:
		return 6;
	case STRING_MAPS_SIZE_7 - 2:
		return 7;
	case STRING_MAPS_SIZE_8 - 2:
		return 8;
	case STRING_MAPS_SIZE_9 - 2:
		return 9;
	}
	return 10;
#else
	if (padded_len == STRING_MAPS_SIZE_6 - 2)
		return 6;
	return 7;
#endif
#else
	return 5;
#endif
}

FUNC_INLINE void *get_string_map(int index, __u32 map_idx)
{
	switch (index) {
	case 0:
		return map_lookup_elem(&string_maps_0, &map_idx);
	case 1:
		return map_lookup_elem(&string_maps_1, &map_idx);
	case 2:
		return map_lookup_elem(&string_maps_2, &map_idx);
	case 3:
		return map_lookup_elem(&string_maps_3, &map_idx);
	case 4:
		return map_lookup_elem(&string_maps_4, &map_idx);
	case 5:
		return map_lookup_elem(&string_maps_5, &map_idx);
#ifdef __LARGE_BPF_PROG
	case 6:
		return map_lookup_elem(&string_maps_6, &map_idx);
	case 7:
		return map_lookup_elem(&string_maps_7, &map_idx);
#ifdef __V511_BPF_PROG
	case 8:
		return map_lookup_elem(&string_maps_8, &map_idx);
	case 9:
		return map_lookup_elem(&string_maps_9, &map_idx);
	case 10:
		return map_lookup_elem(&string_maps_10, &map_idx);
#endif
#endif
	}
	return 0;
}

FUNC_LOCAL long
filter_char_buf_equal(struct selector_arg_filter *filter, char *arg_str, uint orig_len)
{
	__u32 *map_ids = (__u32 *)&filter->value;
	char *heap, *zero_heap;
	void *string_map;
	__u16 padded_len;
	__u32 map_idx;
	int zero = 0;
	__u16 len;
	int index;

#ifdef __LARGE_BPF_PROG
#ifdef __V511_BPF_PROG
	if (orig_len > STRING_MAPS_SIZE_10 - 2 || !orig_len)
		return 0;
#else
	if (orig_len > STRING_MAPS_SIZE_7 - 2 || !orig_len)
		return 0;
#endif
#else
	if (orig_len > STRING_MAPS_SIZE_5 - 1 || !orig_len)
		return 0;
#endif

	len = (__u16)orig_len;
	// Calculate padded string length
	padded_len = string_padded_len(len);

	// Check if we have entries for this padded length.
	// Do this before we copy data for efficiency.
	index = string_map_index(padded_len);
	map_idx = map_ids[index & 0xf];
	if (map_idx == 0xffffffff)
		return 0;

	heap = (char *)map_lookup_elem(&string_maps_heap, &zero);
	zero_heap = (char *)map_lookup_elem(&heap_ro_zero, &zero);
	if (!heap || !zero_heap)
		return 0;

		// Copy string to heap, preceded by length -
		// u8 for first 6 maps; u16 for latter maps
#ifdef __LARGE_BPF_PROG
	if (index <= 5)
		heap[0] = len;
	else
		*(u16 *)heap = len;
#else
	heap[0] = len;
#endif

	asm volatile("%[len] &= %1;\n"
		     : [len] "+r"(len)
		     : "i"(STRING_MAPS_HEAP_MASK));
#ifdef __LARGE_BPF_PROG
	if (index <= 5)
		probe_read(&heap[1], len, arg_str);
	else
		probe_read(&heap[2], len, arg_str);
#else
	probe_read(&heap[1], len, arg_str);
#endif

	// Pad string to multiple of key increment size
	if (padded_len > len) {
		asm volatile("%[len] &= %1;\n"
			     : [len] "+r"(len)
			     : "i"(STRING_MAPS_HEAP_MASK));
#ifdef __LARGE_BPF_PROG
		if (index <= 5)
			probe_read(heap + len + 1, (padded_len - len) & STRING_MAPS_COPY_MASK, zero_heap);
		else
			probe_read(heap + len + 2, (padded_len - len) & STRING_MAPS_COPY_MASK, zero_heap);
#else
		probe_read(heap + len + 1, (padded_len - len) & STRING_MAPS_COPY_MASK, zero_heap);
#endif
	}

	// Get map for this string length
	string_map = get_string_map(index, map_idx);
	if (!string_map)
		return 0;

	__u8 *pass = map_lookup_elem(string_map, heap);

	return !!pass;
}

FUNC_LOCAL long
filter_char_buf_prefix(struct selector_arg_filter *filter, char *arg_str, uint arg_len)
{
	void *addrmap;
	__u32 map_idx = *(__u32 *)&filter->value;
	struct string_prefix_lpm_trie *arg;
	int zero = 0;

	addrmap = map_lookup_elem(&string_prefix_maps, &map_idx);
	if (!addrmap || !arg_len)
		return 0;

	// If the string to check is longer than the prefix map allows, then only check the longest
	// substring that the map allows.
	if (arg_len >= STRING_PREFIX_MAX_LENGTH)
		arg_len = STRING_PREFIX_MAX_LENGTH - 1;

	arg = (struct string_prefix_lpm_trie *)map_lookup_elem(&string_prefix_maps_heap, &zero);
	if (!arg)
		return 0;

	arg->prefixlen = arg_len * 8; // prefix is in bits

	// Force the verifier to recheck the arg_len after register spilling on 4.19.
	asm volatile("%[arg_len] &= %[mask] ;\n"
		     : [arg_len] "+r"(arg_len)
		     : [mask] "i"(STRING_PREFIX_MAX_LENGTH - 1));

	probe_read(arg->data, arg_len & (STRING_PREFIX_MAX_LENGTH - 1), arg_str);

	__u8 *pass = map_lookup_elem(addrmap, arg);

	return !!pass;
}

FUNC_INLINE void __copy_reverse(__u8 *dest, uint len, __u8 *src, uint offset, uint mask)
{
	uint i;

	len &= STRING_POSTFIX_MAX_MASK;
#ifndef __LARGE_BPF_PROG
#pragma unroll
#endif
	// Maximum we can go to is one less than the absolute maximum.
	// This is to allow the masking and indexing to work correctly.
	// (Appreciate this is a bit ugly.)
	// If len == STRING_POSTFIX_MAX_LENGTH, and this is 128, then
	// it will have been masked to 0 above, leading to src indices
	// of -1, -2, -3... masked with STRING_POSTFIX_MAX_MASK (127).
	// These will equal 127, 126, 125... which will therefore
	// reverse copy the string as if it was 127 chars long.
	// Alternative (prettier) fixes resulted in a confused verifier
	// unfortunately.
	for (i = 0; i < (STRING_POSTFIX_MAX_MATCH_LENGTH - 1); i++) {
		dest[i & STRING_POSTFIX_MAX_MASK] = src[(len + offset - 1 - i) & mask];
		if (len + offset == (i + 1))
			return;
	}
}

// Define a mask for the maximum path length on Linux.
#define PATH_MASK (4096 - 1)

FUNC_INLINE void copy_reverse(__u8 *dest, uint len, __u8 *src, uint offset)
{
	__copy_reverse(dest, len, src, offset, PATH_MASK);
}

FUNC_INLINE void file_copy_reverse(__u8 *dest, uint len, __u8 *src, uint offset)
{
	__copy_reverse(dest, len, src, offset, STRING_POSTFIX_MAX_LENGTH - 1);
}

FUNC_LOCAL long
filter_char_buf_postfix(struct selector_arg_filter *filter, char *arg_str, uint arg_len)
{
	void *addrmap;
	__u32 map_idx = *(__u32 *)&filter->value;
	struct string_postfix_lpm_trie *arg;
	uint orig_len = arg_len;
	int zero = 0;

	addrmap = map_lookup_elem(&string_postfix_maps, &map_idx);
	if (!addrmap || !arg_len)
		return 0;

	if (arg_len >= STRING_POSTFIX_MAX_MATCH_LENGTH)
		arg_len = STRING_POSTFIX_MAX_MATCH_LENGTH - 1;

	arg = (struct string_postfix_lpm_trie *)map_lookup_elem(&string_postfix_maps_heap, &zero);
	if (!arg)
		return 0;

	arg->prefixlen = arg_len * 8; // prefix is in bits
	copy_reverse(arg->data, arg_len, (__u8 *)arg_str, orig_len - arg_len);

	__u8 *pass = map_lookup_elem(addrmap, arg);

	return !!pass;
}

FUNC_INLINE bool is_not_operator(__u32 op)
{
	return (op == op_filter_neq || op == op_filter_str_notprefix || op == op_filter_str_notpostfix || op == op_filter_notin);
}

FUNC_LOCAL long
filter_char_buf(struct selector_arg_filter *filter, char *args, int value_off)
{
	long match = 0;
	// Arg length is 4 bytes before the value data
	uint len = *(uint *)&args[value_off - 4];
	char *arg_str = &args[value_off];

	switch (filter->op) {
	case op_filter_eq:
	case op_filter_neq:
		match = filter_char_buf_equal(filter, arg_str, len);
		break;
	case op_filter_str_prefix:
	case op_filter_str_notprefix:
		match = filter_char_buf_prefix(filter, arg_str, len);
		break;
	case op_filter_str_postfix:
	case op_filter_str_notpostfix:
		match = filter_char_buf_postfix(filter, arg_str, len);
		break;
	}

	return is_not_operator(filter->op) ? !match : match;
}

struct string_buf {
	__u32 len;
	char buf[];
};

/* filter_file_buf: runs a comparison between the file path in args against the
 * filter file path. For 'equal' and 'prefix' operators we compare the file path
 * and the filter file path in the normal order. For the 'postfix' operator we do
 * a reverse search.
 */
FUNC_LOCAL long
filter_file_buf(struct selector_arg_filter *filter, struct string_buf *args)
{
	long match = 0;

	/* There are cases where file pointer may not contain a path.
	 * An example is using an unnamed pipe. This is not a match.
	 */
	if (args->len == 0)
		return 0;

	switch (filter->op) {
	case op_filter_eq:
	case op_filter_neq:
		match = filter_char_buf_equal(filter, args->buf, args->len);
		break;
	case op_filter_str_prefix:
	case op_filter_str_notprefix:
		match = filter_char_buf_prefix(filter, args->buf, args->len);
		break;
	case op_filter_str_postfix:
	case op_filter_str_notpostfix:
		match = filter_char_buf_postfix(filter, args->buf, args->len);
		break;
	}

	return is_not_operator(filter->op) ? !match : match;
}

struct ip_ver {
	u8 ihl : 4;
	u8 version : 4;
};

FUNC_INLINE long
filter_addr_op_mod(__u32 op, long value)
{
	switch (op) {
	case op_filter_saddr:
	case op_filter_daddr:
		return !!value;
	case op_filter_notsaddr:
	case op_filter_notdaddr:
		return !value;
	}
	return 0;
}

// use the selector value to determine a LPM Trie map, and do a lookup to determine whether the argument
// is in the defined set.
FUNC_INLINE long
filter_addr_map(struct selector_arg_filter *filter, __u64 *addr, __u16 family)
{
	void *addrmap;
	__u32 *map_idxs = (__u32 *)&filter->value;
	__u32 map_idx;
	struct addr4_lpm_trie arg4;
	struct addr6_lpm_trie arg6;
	void *arg;

	switch (family) {
	case AF_INET:
		map_idx = map_idxs[0];
		addrmap = map_lookup_elem(&addr4lpm_maps, &map_idx);
		if (!addrmap)
			return filter_addr_op_mod(filter->op, 0);
		arg4.prefix = 32;
		arg4.addr = addr[0];
		arg = &arg4;
		break;
	case AF_INET6:
		map_idx = map_idxs[1];
		addrmap = map_lookup_elem(&addr6lpm_maps, &map_idx);
		if (!addrmap)
			return filter_addr_op_mod(filter->op, 0);
		arg6.prefix = 128;
		// write the address in as 4 u32s due to alignment
		write_ipv6_addr32(arg6.addr, (__u32 *)addr);
		arg = &arg6;
		break;
	default:
		return 0;
	}

	long exists = (long)map_lookup_elem(addrmap, arg);

	return filter_addr_op_mod(filter->op, exists);
}

/* filter_inet: runs a comparison between the IPv4/6 addresses and ports in
 * the sock or skb in the args aginst the filter parameters.
 */
FUNC_LOCAL long
filter_inet(struct selector_arg_filter *filter, char *args)
{
	struct sockaddr_in_type *address = 0;
	struct tuple_type *tuple = 0;
	struct tuple_type t = { 0 };
	struct skb_type *skb = 0;
	__u64 addr[2] = { 0, 0 };
	struct sk_type *sk = 0;
	__u32 value = 0;
	__u32 port = 0;

	switch (filter->type) {
	case sock_type:
	case socket_type:
		sk = (struct sk_type *)args;
		tuple = &sk->tuple;
		break;
	case skb_type:
		skb = (struct skb_type *)args;
		tuple = &skb->tuple;
		break;
	case sockaddr_type:
		address = (struct sockaddr_in_type *)args;
		t.family = address->sin_family;
		t.sport = address->sin_port;
		t.saddr[0] = address->sin_addr[0];
		t.saddr[1] = address->sin_addr[1];
		tuple = &t;
		break;
	default:
		return 0;
	}

	switch (filter->op) {
	case op_filter_saddr:
	case op_filter_notsaddr:
		write_ipv6_addr(addr, tuple->saddr);
		break;
	case op_filter_daddr:
	case op_filter_notdaddr:
		write_ipv6_addr(addr, tuple->daddr);
		break;
	case op_filter_sport:
	case op_filter_notsport:
	case op_filter_sportpriv:
	case op_filter_notsportpriv:
		port = tuple->sport;
		break;
	case op_filter_dport:
	case op_filter_notdport:
	case op_filter_dportpriv:
	case op_filter_notdportpriv:
		port = tuple->dport;
		break;
	case op_filter_protocol:
		value = tuple->protocol;
		break;
	case op_filter_family:
		value = tuple->family;
		break;
	case op_filter_state:
		if ((filter->type == sock_type || filter->type == socket_type) && sk)
			value = sk->state;
		break;
	default:
		return 0;
	}

	switch (filter->op) {
	case op_filter_sport:
	case op_filter_dport:
	case op_filter_notsport:
	case op_filter_notdport:
		return filter_32ty_map(filter, (char *)&port);
	case op_filter_sportpriv:
	case op_filter_dportpriv:
		return port < 1024;
	case op_filter_notsportpriv:
	case op_filter_notdportpriv:
		return port >= 1024;
	case op_filter_saddr:
	case op_filter_daddr:
	case op_filter_notsaddr:
	case op_filter_notdaddr:
		return filter_addr_map(filter, addr, tuple->family);
	case op_filter_protocol:
	case op_filter_family:
		return filter_32ty_map(filter, (char *)&value);
	case op_filter_state:
		if (filter->type == sock_type || filter->type == socket_type)
			return filter_32ty_map(filter, (char *)&value);
	}
	return 0;
}

FUNC_INLINE long
__copy_char_iovec(long off, unsigned long arg, unsigned long cnt,
		  unsigned long max, struct msg_generic_kprobe *e)
{
	long size, off_orig = off;
	unsigned long i = 0;
	int *s;

	size = 0;
	off += 8;
	PARSE_IOVEC_ENTRIES // may return an error directly
		/* PARSE_IOVEC_ENTRIES will jump here when done or return error */
		char_iovec_done :

	    s = (int *)args_off(e, off_orig);
	s[0] = size;
	s[1] = size;
	return size + 8;
}

FUNC_INLINE long
copy_char_iovec(void *ctx, long off, unsigned long arg, int argm,
		struct msg_generic_kprobe *e)
{
	int *s = (int *)args_off(e, off);
	unsigned long meta;

	meta = get_arg_meta(argm, e);

	if (has_return_copy(argm)) {
		u64 retid = retprobe_map_get_key(ctx);

		retprobe_map_set_iovec(e->func_id, retid, e->common.ktime, arg, meta);
		return return_error(s, char_buf_saved_for_retprobe);
	}
	return __copy_char_iovec(off, arg, meta, 0, e);
}

FUNC_INLINE long copy_bpf_attr(char *args, unsigned long arg)
{
	union bpf_attr *ba = (union bpf_attr *)arg;
	struct bpf_info_type *bpf_info = (struct bpf_info_type *)args;

	/* struct values */
	probe_read(&bpf_info->prog_type, sizeof(__u32), _(&ba->prog_type));
	probe_read(&bpf_info->insn_cnt, sizeof(__u32), _(&ba->insn_cnt));
	probe_read(&bpf_info->prog_name, BPF_OBJ_NAME_LEN, _(&ba->prog_name));

	return sizeof(struct bpf_info_type);
}

FUNC_INLINE long copy_bpf_prog(char *args, unsigned long arg)
{
	struct bpf_prog *ba = (struct bpf_prog *)arg;
	struct bpf_info_type *bpf_info = (struct bpf_info_type *)args;

	/* struct values */
	bpf_info->prog_type = BPF_CORE_READ(ba, type);
	bpf_info->insn_cnt = BPF_CORE_READ(ba, len);
	BPF_CORE_READ_STR_INTO(&bpf_info->prog_name, ba, aux, name);

	return sizeof(struct bpf_info_type);
}

FUNC_INLINE long copy_perf_event(char *args, unsigned long arg)
{
	struct perf_event *p_event = (struct perf_event *)arg;
	struct perf_event_info_type *event_info =
		(struct perf_event_info_type *)args;

	/* struct values */
	__u64 kprobe_func_addr = 0;

	probe_read(&kprobe_func_addr, sizeof(__u64),
		   _(&p_event->attr.kprobe_func));
	probe_read_str(&event_info->kprobe_func, KSYM_NAME_LEN,
		       (char *)kprobe_func_addr);

	probe_read(&event_info->type, sizeof(__u32), _(&p_event->attr.type));
	probe_read(&event_info->config, sizeof(__u64),
		   _(&p_event->attr.config));
	probe_read(&event_info->probe_offset, sizeof(__u64),
		   _(&p_event->attr.probe_offset));

	return sizeof(struct perf_event_info_type);
}

FUNC_INLINE long copy_bpf_map(char *args, unsigned long arg)
{
	struct bpf_map *bpfmap = (struct bpf_map *)arg;
	struct bpf_map_info_type *map_info = (struct bpf_map_info_type *)args;

	/* struct values */
	probe_read(&map_info->map_type, sizeof(__u32), _(&bpfmap->map_type));
	probe_read(&map_info->key_size, sizeof(__u32), _(&bpfmap->key_size));
	probe_read(&map_info->value_size, sizeof(__u32),
		   _(&bpfmap->value_size));
	probe_read(&map_info->max_entries, sizeof(__u32),
		   _(&bpfmap->max_entries));
	probe_read(&map_info->map_name, BPF_OBJ_NAME_LEN, _(&bpfmap->name));

	return sizeof(struct bpf_map_info_type);
}

FUNC_INLINE bool is_signed_type(int type)
{
	return type == s32_ty || type == s64_ty || type == int_type;
}

// filter on values provided in the selector itself
FUNC_LOCAL long
filter_64ty_selector_val(struct selector_arg_filter *filter, char *args)
{
	__u64 *v = (__u64 *)&filter->value;
	int i, j = 0;

#pragma unroll
	for (i = 0; i < MAX_MATCH_VALUES; i++) {
		__u64 w = v[i];
		bool res;

		switch (filter->op) {
#ifdef __LARGE_BPF_PROG
		case op_filter_lt:
			if (is_signed_type(filter->type)) {
				if (*(s64 *)args < (s64)w)
					return 1;
			} else {
				if (*(u64 *)args < w)
					return 1;
			}
			break;
		case op_filter_gt:
			if (is_signed_type(filter->type)) {
				if (*(s64 *)args > (s64)w)
					return 1;
			} else {
				if (*(u64 *)args < w)
					return 1;
			}
			break;
#endif // __LARGE_BPF_PROG
		case op_filter_eq:
		case op_filter_neq:
			res = (*(u64 *)args == w);
			if (filter->op == op_filter_eq && res)
				return 1;
			if (filter->op == op_filter_neq && !res)
				return 1;
			break;
		case op_filter_mask:
			if (*(u64 *)args & w)
				return 1;
			break;
		default:
			break;
		}
		j += 8;
		if (j + 8 >= filter->vallen)
			break;
	}
	return 0;
}

// filter on values provided in the selector itself
FUNC_LOCAL long
filter_8ty_selector_val(struct selector_arg_filter *filter, char *args)
{
	__u32 *v = (__u32 *)&filter->value;
	int i, j = 0;

#pragma unroll
	for (i = 0; i < MAX_MATCH_VALUES; i++) {
		__u32 w = v[i];
		bool res;

		switch (filter->op) {
		case op_filter_lt:
			if (is_signed_type(filter->type)) {
				if (*(s8 *)args < (s32)w)
					return 1;
			} else {
				if (*(u8 *)args < w)
					return 1;
			}
			break;
		case op_filter_gt:
			if (is_signed_type(filter->type)) {
				if (*(s8 *)args > (s32)w)
					return 1;
			} else {
				if (*(u8 *)args < w)
					return 1;
			}
			break;
		case op_filter_eq:
		case op_filter_neq:
			res = (*(u8 *)args == w);
			if (filter->op == op_filter_eq && res)
				return 1;
			if (filter->op == op_filter_neq && !res)
				return 1;
			break;
		case op_filter_mask:
			if (*(u8 *)args & w)
				return 1;
			break;
		default:
			break;
		}
		// placed here to allow llvm unroll this loop
		j += 4;
		// + 8 because the the members vallen (uint32) and type (uint32) are included
		// in the total stored in filter->vallen. see func parseMatchArg()
		if (j + 8 >= filter->vallen)
			break;
	}
	return 0;
}

// use the selector value to determine a hash map, and do a lookup to determine whether the argument
// is in the defined set.
FUNC_LOCAL long
filter_8ty_map(struct selector_arg_filter *filter, char *args)
{
	void *argmap;
	__u32 map_idx = filter->value;

	argmap = map_lookup_elem(&argfilter_maps, &map_idx);
	if (!argmap)
		return 0;

	__u64 arg = *((__u8 *)args);
	__u8 *pass = map_lookup_elem(argmap, &arg);

	switch (filter->op) {
	case op_filter_inmap:
	case op_filter_sport:
	case op_filter_dport:
	case op_filter_protocol:
	case op_filter_family:
	case op_filter_state:
		return !!pass;
	case op_filter_notinmap:
	case op_filter_notsport:
	case op_filter_notdport:
		return !pass;
	}
	return 0;
}

// filter on values provided in the selector itself
FUNC_LOCAL long
filter_16ty_selector_val(struct selector_arg_filter *filter, char *args)
{
	__u32 *v = (__u32 *)&filter->value;
	int i, j = 0;

#pragma unroll
	for (i = 0; i < MAX_MATCH_VALUES; i++) {
		__u32 w = v[i];
		bool res;

		switch (filter->op) {
		case op_filter_lt:
			if (is_signed_type(filter->type)) {
				if (*(s16 *)args < (s32)w)
					return 1;
			} else {
				if (*(u16 *)args < w)
					return 1;
			}
			break;
		case op_filter_gt:
			if (is_signed_type(filter->type)) {
				if (*(s16 *)args > (s32)w)
					return 1;
			} else {
				if (*(u16 *)args < w)
					return 1;
			}
			break;
		case op_filter_eq:
		case op_filter_neq:
			res = (*(u16 *)args == w);
			if (filter->op == op_filter_eq && res)
				return 1;
			if (filter->op == op_filter_neq && !res)
				return 1;
			break;
		case op_filter_mask:
			if (*(u16 *)args & w)
				return 1;
			break;
		default:
			break;
		}
		// placed here to allow llvm unroll this loop
		j += 4;
		// + 8 because the the members vallen (uint32) and type (uint32) are included
		// in the total stored in filter->vallen. see func parseMatchArg()
		if (j + 8 >= filter->vallen)
			break;
	}
	return 0;
}

// use the selector value to determine a hash map, and do a lookup to determine whether the argument
// is in the defined set.
FUNC_LOCAL long
filter_16ty_map(struct selector_arg_filter *filter, char *args)
{
	void *argmap;
	__u32 map_idx = filter->value;

	argmap = map_lookup_elem(&argfilter_maps, &map_idx);
	if (!argmap)
		return 0;

	__u64 arg = *((__u16 *)args);
	__u8 *pass = map_lookup_elem(argmap, &arg);

	switch (filter->op) {
	case op_filter_inmap:
	case op_filter_sport:
	case op_filter_dport:
	case op_filter_protocol:
	case op_filter_family:
	case op_filter_state:
		return !!pass;
	case op_filter_notinmap:
	case op_filter_notsport:
	case op_filter_notdport:
		return !pass;
	}
	return 0;
}

// use the selector value to determine a hash map, and do a lookup to determine whether the argument
// is in the defined set.
FUNC_LOCAL long
filter_64ty_map(struct selector_arg_filter *filter, char *args)
{
	void *argmap;
	__u32 map_idx = filter->value;

	argmap = map_lookup_elem(&argfilter_maps, &map_idx);
	if (!argmap)
		return 0;

	__u64 arg = *((__u64 *)args);
	__u8 *pass = map_lookup_elem(argmap, &arg);

	switch (filter->op) {
	case op_filter_inmap:
		return !!pass;
	case op_filter_notinmap:
		return !pass;
	}
	return 0;
}

FUNC_LOCAL long
filter_64ty_range(struct selector_arg_filter *filter, char *args)
{
	__u64 *v = (__u64 *)&filter->value;
	int all = 0, i, j = 0;

#pragma unroll
	for (i = 0; i < MAX_MATCH_VALUES; i++) {
		__u64 start = v[i * 2], end = v[i * 2 + 1];
		bool res;

		if (is_signed_type(filter->type))
			res = ((__s64)start <= *(s64 *)args) && (*(s64 *)args <= (__s64)end);
		else
			res = (start <= *(u64 *)args) && (*(u64 *)args <= end);

		if (filter->op == op_in_range && res)
			return 1;
		all |= res;

		j += sizeof(*v) * 2;
		if (j + 8 /* vallen+type */ >= filter->vallen)
			break;
	}
	if (filter->op == op_notin_range && !all)
		return 1;
	return 0;
}

FUNC_LOCAL long
filter_32ty_range(struct selector_arg_filter *filter, char *args)
{
	__u32 *v = (__u32 *)&filter->value;
	int all = 0, i, j = 0;

#pragma unroll
	for (i = 0; i < MAX_MATCH_VALUES; i++) {
		__u32 start = v[i * 2], end = v[i * 2 + 1];
		bool res;

		if (is_signed_type(filter->type))
			res = ((__s32)start <= *(s32 *)args) && (*(s32 *)args <= (__s32)end);
		else
			res = (start <= *(u32 *)args) && (*(u32 *)args <= end);

		if (filter->op == op_in_range && res)
			return 1;
		all |= res;

		j += sizeof(*v) * 2;
		if (j + 8 /* vallen+type */ >= filter->vallen)
			break;
	}
	if (filter->op == op_notin_range && !all)
		return 1;
	return 0;
}

FUNC_LOCAL long
filter_16ty_range(struct selector_arg_filter *filter, char *args)
{
	__u32 *v = (__u32 *)&filter->value;
	int all = 0, i, j = 0;

#pragma unroll
	for (i = 0; i < MAX_MATCH_VALUES; i++) {
		__u32 start = v[i * 2], end = v[i * 2 + 1];
		bool res;

		if (is_signed_type(filter->type))
			res = ((__s32)start <= *(s16 *)args) && (*(s16 *)args <= (__s32)end);
		else
			res = (start <= *(u16 *)args) && (*(u16 *)args <= end);

		if (filter->op == op_in_range && res)
			return 1;
		all |= res;

		j += sizeof(*v) * 2;
		if (j + 8 /* vallen+type */ >= filter->vallen)
			break;
	}
	if (filter->op == op_notin_range && !all)
		return 1;
	return 0;
}

FUNC_LOCAL long
filter_8ty_range(struct selector_arg_filter *filter, char *args)
{
	__u32 *v = (__u32 *)&filter->value;
	int all = 0, i, j = 0;

#pragma unroll
	for (i = 0; i < MAX_MATCH_VALUES; i++) {
		__u32 start = v[i * 2], end = v[i * 2 + 1];
		bool res;

		if (is_signed_type(filter->type))
			res = ((__s32)start <= *(s8 *)args) && (*(s8 *)args <= (__s32)end);
		else
			res = (start <= *(u8 *)args) && (*(u8 *)args <= end);

		if (filter->op == op_in_range && res)
			return 1;
		all |= res;

		j += sizeof(*v) * 2;
		if (j + 8 /* vallen+type */ >= filter->vallen)
			break;
	}
	if (filter->op == op_notin_range && !all)
		return 1;
	return 0;
}

FUNC_LOCAL long
filter_64ty(struct selector_arg_filter *filter, char *args)
{
	switch (filter->op) {
	case op_filter_lt:
	case op_filter_gt:
	case op_filter_eq:
	case op_filter_neq:
	case op_filter_mask:
		return filter_64ty_selector_val(filter, args);
	case op_filter_inmap:
	case op_filter_notinmap:
		return filter_64ty_map(filter, args);
#ifdef __LARGE_BPF_PROG
	case op_in_range:
	case op_notin_range:
		return filter_64ty_range(filter, args);
#endif
	}

	return 0;
}

FUNC_LOCAL long
filter_32ty_selector_val(struct selector_arg_filter *filter, char *args)
{
	__u32 *v = (__u32 *)&filter->value;
	int i, j = 0;

#pragma unroll
	for (i = 0; i < MAX_MATCH_VALUES; i++) {
		__u32 w = v[i];
		bool res;

		switch (filter->op) {
#ifdef __LARGE_BPF_PROG
		case op_filter_lt:
			if (is_signed_type(filter->type)) {
				if (*(s32 *)args < (s32)w)
					return 1;
			} else {
				if (*(u32 *)args < w)
					return 1;
			}
			break;
		case op_filter_gt:
			if (is_signed_type(filter->type)) {
				if (*(s32 *)args > (s32)w)
					return 1;
			} else {
				if (*(u32 *)args > w)
					return 1;
			}
			break;
#endif // __LARGE_BPF_PROG
		case op_filter_eq:
		case op_filter_neq:
			res = (*(u32 *)args == w);

			if (filter->op == op_filter_eq && res)
				return 1;
			if (filter->op == op_filter_neq && !res)
				return 1;
			break;
		case op_filter_mask:
			if (*(u32 *)args & w)
				return 1;
			break;
		default:
			break;
		}
		// placed here to allow llvm unroll this loop
		j += 4;
		if (j + 8 >= filter->vallen)
			break;
	}
	return 0;
}

// use the selector value to determine a hash map, and do a lookup to determine whether the argument
// is in the defined set.
FUNC_LOCAL long
filter_32ty_map(struct selector_arg_filter *filter, char *args)
{
	void *argmap;
	__u32 map_idx = filter->value;

	argmap = map_lookup_elem(&argfilter_maps, &map_idx);
	if (!argmap)
		return 0;

	__u64 arg = *((__u32 *)args);
	__u8 *pass = map_lookup_elem(argmap, &arg);

	switch (filter->op) {
	case op_filter_inmap:
	case op_filter_sport:
	case op_filter_dport:
	case op_filter_protocol:
	case op_filter_family:
	case op_filter_state:
		return !!pass;
	case op_filter_notinmap:
	case op_filter_notsport:
	case op_filter_notdport:
		return !pass;
	}
	return 0;
}

FUNC_LOCAL long
filter_32ty(struct selector_arg_filter *filter, char *args)
{
	switch (filter->op) {
	case op_filter_lt:
	case op_filter_gt:
	case op_filter_eq:
	case op_filter_neq:
	case op_filter_mask:
		return filter_32ty_selector_val(filter, args);
	case op_filter_inmap:
	case op_filter_notinmap:
		return filter_32ty_map(filter, args);
#ifdef __LARGE_BPF_PROG
	case op_in_range:
	case op_notin_range:
		return filter_32ty_range(filter, args);
#endif
	}

	return 0;
}

FUNC_LOCAL long
filter_16ty(struct selector_arg_filter *filter, char *args)
{
	switch (filter->op) {
	case op_filter_lt:
	case op_filter_gt:
	case op_filter_eq:
	case op_filter_neq:
	case op_filter_mask:
		return filter_16ty_selector_val(filter, args);
	case op_filter_inmap:
	case op_filter_notinmap:
		return filter_16ty_map(filter, args);
#ifdef __LARGE_BPF_PROG
	case op_in_range:
	case op_notin_range:
		return filter_16ty_range(filter, args);
#endif
	}

	return 0;
}

FUNC_LOCAL long
filter_8ty(struct selector_arg_filter *filter, char *args)
{
	switch (filter->op) {
	case op_filter_lt:
	case op_filter_gt:
	case op_filter_eq:
	case op_filter_neq:
	case op_filter_mask:
		return filter_8ty_selector_val(filter, args);
	case op_filter_inmap:
	case op_filter_notinmap:
		return filter_8ty_map(filter, args);
#ifdef __LARGE_BPF_PROG
	case op_in_range:
	case op_notin_range:
		return filter_8ty_range(filter, args);
#endif
	}

	return 0;
}

FUNC_INLINE size_t type_to_min_size(int type, int argm)
{
	switch (type) {
	case fd_ty:
	case file_ty:
	case path_ty:
	case dentry_type:
	case string_type:
		return MAX_STRING;
	case int_type:
	case s32_ty:
	case u32_ty:
	case s16_ty:
	case u16_ty:
	case s8_ty:
	case u8_ty:
		return 4;
	case skb_type:
		return sizeof(struct skb_type);
	case sock_type:
	case socket_type:
		return sizeof(struct sk_type);
	case sockaddr_type:
		return sizeof(struct sockaddr_in_type);
	case cred_type:
		return sizeof(struct msg_cred);
	case size_type:
	case s64_ty:
	case u64_ty:
	case kernel_cap_ty:
	case cap_inh_ty:
	case cap_prm_ty:
	case cap_eff_ty:
		return 8;
	case char_buf:
	case char_iovec:
		return 4;
	case const_buf_type:
		return argm;
	case bpf_attr_type:
	case bpf_prog_type:
		return sizeof(struct bpf_info_type);
	case perf_event_type:
		return sizeof(struct perf_event_info_type);
	case bpf_map_type:
		return sizeof(struct bpf_map_info_type);
	case user_namespace_type:
		return sizeof(struct msg_user_namespace);
	case capability_type:
		return sizeof(struct capability_info_type);
	case load_module_type:
		return sizeof(struct tg_kernel_module);
	case kernel_module_type:
		return sizeof(struct tg_kernel_module);
	case linux_binprm_type:
		return sizeof(struct msg_linux_binprm);
	case net_dev_ty:
		return IFNAMSIZ;
	// nop or something else we do not process here
	default:
		return 0;
	}
}

#define INDEX_MASK 0x3ff

struct match_binaries_sel_opts {
	__u32 op;
	__u32 map_id;
	__u32 mbset_id;
};

// This map is used by the matchBinaries selectors to retrieve their options
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_SELECTORS);
	__type(key, __u32); /* selector id */
	__type(value, struct match_binaries_sel_opts);
} tg_mb_sel_opts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
	__uint(max_entries, MAX_SELECTORS); // only one matchBinaries per selector
	__type(key, __u32);
	__array(
		values, struct {
			__uint(type, BPF_MAP_TYPE_HASH);
			__uint(max_entries, 1);
			__type(key, __u8[MATCH_BINARIES_PATH_MAX_LENGTH]);
			__type(value, __u8);
		});
} tg_mb_paths SEC(".maps");

FUNC_INLINE int match_binaries(__u32 selidx, struct execve_map_value *current)
{
	bool match = 0;
	void *path_map;
	__u8 *found_key;
#ifdef __LARGE_BPF_PROG
	struct string_prefix_lpm_trie prefix_key;
	struct string_postfix_lpm_trie *postfix_key;
	__u64 postfix_len = STRING_POSTFIX_MAX_MATCH_LENGTH - 1;

	int zero = 0;
#endif /* __LARGE_BPF_PROG */

	struct match_binaries_sel_opts *selector_options;

	// retrieve the selector_options for the matchBinaries, if it's NULL it
	// means there is not matchBinaries in this selector.
	selector_options = map_lookup_elem(&tg_mb_sel_opts, &selidx);
	if (selector_options) {
		if (selector_options->op == op_filter_none)
			return 1; // matchBinaries selector is empty <=> match

		if (current->bin.path_length < 0) {
			// something wrong happened when copying the filename to execve_map
			return 0;
		}

		switch (selector_options->op) {
		case op_filter_in:
		case op_filter_notin:
			update_mb_task(current);

			/* Check if we match the selector's bit in ->mb_bitset, which means that the
			 * process matches a matchBinaries section with a followChidren:true
			 * attribute either because the binary matches or because the binary of a
			 * parent matched.
			 */
			if (selector_options->mbset_id != MBSET_INVALID_ID &&
			    (current->bin.mb_bitset & (1UL << selector_options->mbset_id))) {
				found_key = (u8 *)0xbadc0ffee;
				break;
			}

			path_map = map_lookup_elem(&tg_mb_paths, &selidx);
			if (!path_map)
				return 0;
			found_key = map_lookup_elem(path_map, current->bin.path);
			break;
#ifdef __LARGE_BPF_PROG
		case op_filter_str_prefix:
		case op_filter_str_notprefix:
			path_map = map_lookup_elem(&string_prefix_maps, &selector_options->map_id);
			if (!path_map)
				return 0;
			// prepare the key on the stack to perform lookup in the LPM_TRIE
			memset(&prefix_key, 0, sizeof(prefix_key));
			prefix_key.prefixlen = current->bin.path_length * 8; // prefixlen is in bits
			if (probe_read(prefix_key.data, current->bin.path_length & (STRING_PREFIX_MAX_LENGTH - 1), current->bin.path) < 0)
				return 0;
			found_key = map_lookup_elem(path_map, &prefix_key);
			break;
		case op_filter_str_postfix:
		case op_filter_str_notpostfix:
			path_map = map_lookup_elem(&string_postfix_maps, &selector_options->map_id);
			if (!path_map)
				return 0;
			if (current->bin.path_length < STRING_POSTFIX_MAX_MATCH_LENGTH)
				postfix_len = current->bin.path_length;
			postfix_key = (struct string_postfix_lpm_trie *)map_lookup_elem(&string_postfix_maps_heap, &zero);
			if (!postfix_key)
				return 0;
			postfix_key->prefixlen = postfix_len * 8; // prefixlen is in bits
			if (!current->bin.reversed) {
				file_copy_reverse((__u8 *)current->bin.end_r, postfix_len, (__u8 *)current->bin.end, current->bin.path_length - postfix_len);
				current->bin.reversed = true;
			}
			if (postfix_len < STRING_POSTFIX_MAX_MATCH_LENGTH)
				if (probe_read(postfix_key->data, postfix_len, current->bin.end_r) < 0)
					return 0;
			found_key = map_lookup_elem(path_map, postfix_key);
			break;
#endif /* __LARGE_BPF_PROG */
		default:
			// should not happen
			return 0;
		}

		match = !!found_key;
		return is_not_operator(selector_options->op) ? !match : match;
	}

	// no matchBinaries selector <=> match
	return 1;
}

FUNC_INLINE char *
get_arg(struct msg_generic_kprobe *e, __u32 index)
{
	long argoff;

	asm volatile("%[index] &= 0x7;\n" : [index] "+r"(index));
	argoff = e->argsoff[index];
	asm volatile("%[argoff] &= 0x7ff;\n" : [argoff] "+r"(argoff));
	return &e->args[argoff];
}

FUNC_INLINE int
selector_arg_offset(__u8 *f, struct msg_generic_kprobe *e, __u32 selidx,
		    bool is_entry)
{
	struct selector_arg_filters *filters;
	struct selector_arg_filter *filter;
	long seloff, argsoff, pass = 1, margsoff;
	__u32 i = 0, index;
	char *args;

	seloff = 4; /* start of the relative offsets */
	seloff += (selidx * 4); /* relative offset for this selector */

	/* selector section offset by reading the relative offset in the array */
	seloff += *(__u32 *)((__u64)f + (seloff & INDEX_MASK));

	/* skip the selector size field */
	seloff += 4;

	/* skip selectors defined only for entry probe */
	if (is_entry) {
		/* skip the matchPids section by reading its length */
		seloff += *(__u32 *)((__u64)f + (seloff & INDEX_MASK));
		/* skip the matchNamespaces section by reading its length*/
		seloff += *(__u32 *)((__u64)f + (seloff & INDEX_MASK));
		/* skip matchCapabilitiess section by reading its length */
		seloff += *(__u32 *)((__u64)f + (seloff & INDEX_MASK));
		/* skip the matchNamespaceChanges by reading its length */
		seloff += *(__u32 *)((__u64)f + (seloff & INDEX_MASK));
		/* skip the matchCapabilityChanges by reading its length */
		seloff += *(__u32 *)((__u64)f + (seloff & INDEX_MASK));
	}

	/* Making binary selectors fixes size helps on some kernels */
	seloff &= INDEX_MASK;
	filters = (struct selector_arg_filters *)&f[seloff];

	if (filters->arglen <= sizeof(struct selector_arg_filters)) // no filters
		return seloff;

#ifdef __LARGE_BPF_PROG
	for (i = 0; i < 5; i++)
#endif
	{
		argsoff = filters->argoff[i];
		asm volatile("%[argsoff] &= 0x3ff;\n"
			     : [argsoff] "+r"(argsoff));

		if (argsoff <= 0)
			return pass ? seloff : 0;

		margsoff = (seloff + argsoff) & INDEX_MASK;
		filter = (struct selector_arg_filter *)&f[margsoff];

		index = filter->index;
		if (index > 5)
			return 0;

		args = get_arg(e, index);
		switch (filter->type) {
		case fd_ty:
			/* Advance args past fd */
			args += 4;
			fallthrough;
		case file_ty:
		case path_ty:
		case dentry_type:
#ifdef __LARGE_BPF_PROG
		case linux_binprm_type:
#endif
			pass &= filter_file_buf(filter, (struct string_buf *)args);
			break;
		case string_type:
		case net_dev_ty:
		case data_loc_type:
			/* for strings, we just encode the length */
			pass &= filter_char_buf(filter, args, 4);
			break;
		case char_buf:
			/* for buffers, we just encode the expected length and the
			 * length that was actually read (see: __copy_char_buf)
			 */
			pass &= filter_char_buf(filter, args, 8);
			break;
		case cap_inh_ty:
		case cap_prm_ty:
		case cap_eff_ty:
		case kernel_cap_ty:
#ifdef __LARGE_BPF_PROG
			if (filter->op == op_capabilities_gained) {
				__u64 cap_old = *(__u64 *)args;
				__u32 index2 = *((__u32 *)&filter->value);
				__u64 cap_new = *(__u64 *)get_arg(e, index2);

				pass = !!((cap_old ^ cap_new) & cap_new);
				break;
			}
			fallthrough;
#endif
		case syscall64_type:
		case s64_ty:
		case u64_ty:
			pass &= filter_64ty(filter, args);
			break;
		case size_type:
		case int_type:
		case s32_ty:
		case u32_ty:
			pass &= filter_32ty(filter, args);
			break;
#ifdef __LARGE_BPF_PROG
		case s16_ty:
		case u16_ty:
			pass &= filter_16ty(filter, args);
			break;
		case s8_ty:
		case u8_ty:
			pass &= filter_8ty(filter, args);
			break;
#endif // __LARGE_BPF_PROG
		case skb_type:
		case sock_type:
		case socket_type:
		case sockaddr_type:
			pass &= filter_inet(filter, args);
			break;
		default:
			break;
		}
	}
	return pass ? seloff : 0;
}

FUNC_INLINE int filter_args_reject(u64 id)
{
	u64 tid = get_current_pid_tgid();
	retprobe_map_clear(id, tid);
	return 0;
}

struct fdinstall_key {
	__u64 tid;
	__u32 fd;
	__u32 pad;
};

struct fdinstall_value {
	char file[4104]; // 4096B paths + 4B length + 4B flags
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1); // will be resized by agent when needed
	__type(key, struct fdinstall_key);
	__type(value, struct fdinstall_value);
} fdinstall_map SEC(".maps");

FUNC_INLINE int
installfd(struct msg_generic_kprobe *e, int fd, int name, bool follow)
{
	struct fdinstall_key key = { 0 };
	struct fdinstall_value *val;
	int err = 0, zero = 0;
	long fdoff, nameoff;

	val = map_lookup_elem(&heap, &zero);
	if (!val)
		return 0;

	/* Satisfies verifier but is a bit ugly, ideally we
	 * can just '&' and drop the '>' case.
	 */
	asm volatile("%[fd] &= 0xf;\n"
		     : [fd] "+r"(fd)
		     :);
	if (fd > 5) {
		return 0;
	}
	fdoff = e->argsoff[fd];
	asm volatile("%[fdoff] &= 0x7ff;\n"
		     : [fdoff] "+r"(fdoff)
		     :);
	key.pad = 0;
	key.fd = *(__u32 *)&e->args[fdoff];
	key.tid = get_current_pid_tgid() >> 32;

	if (follow) {
		__u32 size;

		asm volatile("%[name] &= 0xf;\n"
			     : [name] "+r"(name)
			     :);
		if (name > 5)
			return 0;
		nameoff = e->argsoff[name];
		asm volatile("%[nameoff] &= 0x7ff;\n"
			     : [nameoff] "+r"(nameoff)
			     :);

		size = *(__u32 *)&e->args[nameoff];
		asm volatile("%[size] &= 0xfff;\n"
			     : [size] "+r"(size)
			     :);

		probe_read(&val->file[0], size + 4 /* size */ + 4 /* flags */,
			   &e->args[nameoff]);

		map_update_elem(&fdinstall_map, &key, val, BPF_ANY);
	} else {
		err = map_delete_elem(&fdinstall_map, &key);
	}
	return err;
}

FUNC_INLINE __u64
msg_generic_arg_value_u64(struct msg_generic_kprobe *e, unsigned int arg_id, __u64 err_val)
{
	__u32 argoff;
	__u64 *ret;

	if (arg_id > MAX_POSSIBLE_ARGS)
		return err_val;
	argoff = e->argsoff[arg_id];
	argoff &= GENERIC_MSG_ARGS_MASK;
	ret = (__u64 *)&e->args[argoff];
	return *ret;
}

FUNC_INLINE int
copyfd(struct msg_generic_kprobe *e, int oldfd, int newfd)
{
	struct fdinstall_key key = { 0 };
	struct fdinstall_value *val;
	int oldfdoff, newfdoff;
	int err = 0;

	asm volatile("%[oldfd] &= 0xf;\n"
		     : [oldfd] "+r"(oldfd)
		     :);
	if (oldfd > 5)
		return 0;
	oldfdoff = e->argsoff[oldfd];
	asm volatile("%[oldfdoff] &= 0x7ff;\n"
		     : [oldfdoff] "+r"(oldfdoff)
		     :);
	key.pad = 0;
	key.fd = *(__u32 *)&e->args[oldfdoff];
	key.tid = get_current_pid_tgid() >> 32;

	val = map_lookup_elem(&fdinstall_map, &key);
	if (val) {
		asm volatile("%[newfd] &= 0xf;\n"
			     : [newfd] "+r"(newfd)
			     :);
		if (newfd > 5)
			return 0;
		newfdoff = e->argsoff[newfd];
		asm volatile("%[newfdoff] &= 0x7ff;\n"
			     : [newfdoff] "+r"(newfdoff)
			     :);
		key.pad = 0;
		key.fd = *(__u32 *)&e->args[newfdoff];
		key.tid = get_current_pid_tgid() >> 32;

		map_update_elem(&fdinstall_map, &key, val, BPF_ANY);
	}

	return err;
}

#ifdef __LARGE_BPF_PROG
FUNC_INLINE void do_action_signal(int signal)
{
	send_signal(signal);
}
#else
#define do_action_signal(signal)
#endif /* __LARGE_BPF_PROG */

#ifdef __LARGE_BPF_PROG
FUNC_INLINE bool
rate_limit(__u64 ratelimit_interval, __u64 ratelimit_scope, struct msg_generic_kprobe *e)
{
	__u64 curr_time = tg_get_ktime();
	__u64 *last_repeat_entry;
	struct ratelimit_key *key;
	void *ro_heap;
	__u32 zero = 0;
	__u32 index = 0;
	__u32 key_index = 0;
	int arg_size;
	int i;
	__u8 *dst;

	if (!ratelimit_interval)
		return false;

	key = map_lookup_elem(&ratelimit_heap, &zero);
	if (!key)
		return false;
	ro_heap = map_lookup_elem(&heap_ro_zero, &zero);

	key->func_id = e->func_id;
	key->action = e->action;
	switch (ratelimit_scope) {
	case ACTION_RATE_LIMIT_SCOPE_THREAD:
		key->tid = e->tid;
		break;
	case ACTION_RATE_LIMIT_SCOPE_PROCESS:
		key->tid = e->current.pid;
		break;
	case ACTION_RATE_LIMIT_SCOPE_GLOBAL:
		key->tid = 0;
		break;
	default:
		return false;
	}

	// Clean the heap
	probe_read(key->data, MAX_POSSIBLE_ARGS * KEY_BYTES_PER_ARG, ro_heap);
	dst = key->data;

	for (i = 0; i < MAX_POSSIBLE_ARGS; i++) {
		if (e->argsoff[i] >= e->common.size)
			break;
		if (i < MAX_POSSIBLE_ARGS - 1)
			arg_size = e->argsoff[i + 1] - e->argsoff[i];
		else
			arg_size = e->common.size - e->argsoff[i];
		if (arg_size > 0) {
			key_index = e->argsoff[i] & 16383;
			if (arg_size > KEY_BYTES_PER_ARG)
				arg_size = KEY_BYTES_PER_ARG;
			asm volatile("%[arg_size] &= 0x3f;\n" // ensure this mask is greater than KEY_BYTES_PER_ARG
				     : [arg_size] "+r"(arg_size)
				     :);
			asm volatile("%[index] &= 0xff;\n"
				     : [index] "+r"(index)
				     :);
			probe_read(&dst[index], arg_size, &e->args[key_index]);
			index += arg_size;
		}
	}

	last_repeat_entry = map_lookup_elem(&ratelimit_map, key);
	if (last_repeat_entry) {
		/* ratelimit_interval is in milliseconds. */
		if (*last_repeat_entry > curr_time - (ratelimit_interval * 1000000)) {
			/* This event is too soon after the last matching event. */
			return true;
		}
	}
	/* As we're acting on this event, update the map with the current time. */
	map_update_elem(&ratelimit_map, key, &curr_time, 0);
	return false;
}
#endif

#ifdef __LARGE_BPF_PROG
struct socket_owner {
	__u32 pid;
	__u32 tid;
	__u64 ktime;
};

// socktrack_map maintains a mapping of sock to pid_tgid
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1); // will be resized by agent when needed
	__type(key, __u64);
	__type(value, struct socket_owner);
} socktrack_map SEC(".maps");

FUNC_INLINE int
tracksock(struct msg_generic_kprobe *e, int socki, bool track)
{
	long sockoff;
	__u64 sockaddr;
	__u64 pid_tgid;
	struct sk_type *skt;
	struct socket_owner owner;
	__u32 pid;
	struct execve_map_value *value;

	/* Satisfies verifier but is a bit ugly, ideally we
	 * can just '&' and drop the '>' case.
	 */
	asm volatile("%[socki] &= 0xf;\n"
		     : [socki] "+r"(socki)
		     :);
	if (socki > 5)
		return 0;

	sockoff = e->argsoff[socki];
	asm volatile("%[sockoff] &= 0x7ff;\n"
		     : [sockoff] "+r"(sockoff)
		     :);
	skt = (struct sk_type *)&e->args[sockoff];
	sockaddr = skt->sockaddr;
	if (!sockaddr)
		return 0;
	if (!track)
		return map_delete_elem(&socktrack_map, &sockaddr);
	pid_tgid = get_current_pid_tgid();
	pid = pid_tgid >> 32;
	value = execve_map_get_noinit(pid);
	if (!value)
		return 0;
	owner.pid = value->key.pid;
	owner.tid = (__u32)pid_tgid;
	owner.ktime = value->key.ktime;

	map_update_elem(&socktrack_map, &sockaddr, &owner, BPF_ANY);
	return 0;
}

/* update_pid_tid_from_sock(e, sock)
 *
 * Look up the socket in the map and populate the pid and tid.
 */
FUNC_INLINE void
update_pid_tid_from_sock(struct msg_generic_kprobe *e, __u64 sockaddr)
{
	struct socket_owner *owner;

	owner = map_lookup_elem(&socktrack_map, &sockaddr);
	if (!owner)
		return;

	e->current.pid = owner->pid;
	e->current.ktime = owner->ktime;
	e->tid = owner->tid;
}
#else
FUNC_INLINE int
tracksock(struct msg_generic_kprobe *e, int socki, bool track)
{
	return 0;
}

FUNC_INLINE void
update_pid_tid_from_sock(struct msg_generic_kprobe *e, __u64 sockaddr)
{
}
#endif

// from linux/perf_event.h, note that this can be controlled with sysctl kernel.perf_event_max_stack
#define PERF_MAX_STACK_DEPTH 127
struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 1); // Agent is resizing this if the feature is needed during kprobe load
	__type(key, __u32);
	__uint(value_size, sizeof(__u64) * PERF_MAX_STACK_DEPTH);
} stack_trace_map SEC(".maps");

#if defined GENERIC_TRACEPOINT || defined GENERIC_KPROBE
FUNC_INLINE void do_action_notify_enforcer(struct msg_generic_kprobe *e,
					   int error, int signal, int info_arg_id)
{
	__u64 argv = msg_generic_arg_value_u64(e, info_arg_id, 0);
	struct enforcer_act_info info = {
		.func_id = e->func_id,
		.arg = argv,
	};
	do_enforcer_action(error, signal, info);
}
#else
#define do_action_notify_enforcer(e, error, signal, info_arg_id)
#endif

FUNC_INLINE void path_from_dentry(struct dentry *dentry, struct path *path_buf)
{
	/*
	 * The dentry type path extraction does not pass through mount
	 * points, setting mnt to NULL to stop d_path_local at first one.
	 */
	path_buf->mnt = NULL;
	path_buf->dentry = dentry;
}

FUNC_INLINE const struct path *get_path(long type, unsigned long arg, struct path *path_buf)
{
	const struct path *path_arg = 0;
	struct kiocb *kiocb;
	struct file *file;

	switch (type) {
	case kiocb_type:
		kiocb = (struct kiocb *)arg;
		arg = (unsigned long)_(&kiocb->ki_filp);
		probe_read(&file, sizeof(file), (const void *)arg);
		arg = (unsigned long)file;
		fallthrough;
	case file_ty:
		probe_read(&file, sizeof(file), &arg);
		path_arg = _(&file->f_path);
		break;
	case path_ty:
		probe_read(&path_arg, sizeof(path_arg), &arg);
		break;
	case dentry_type:
		path_from_dentry((struct dentry *)arg, path_buf);
		path_arg = path_buf;
		break;
#ifdef __LARGE_BPF_PROG
	case linux_binprm_type: {
		struct linux_binprm *bprm = (struct linux_binprm *)arg;

		arg = (unsigned long)_(&bprm->file);
		probe_read(&file, sizeof(file), (const void *)arg);
		path_arg = _(&file->f_path);
		break;
	};
#endif
	}
	return path_arg;
}

#define __STR(x) #x

#define set_if_not_errno_or_zero(x, y)                  \
	({                                              \
		asm volatile("if %0 s< -4095 goto +1\n" \
			     "if %0 s<= 0 goto +1\n"    \
			     "%0 = " __STR(y) "\n"      \
			     : "+r"(x));                \
	})

FUNC_INLINE int try_override(void *ctx, struct bpf_map_def *override_tasks)
{
	__u64 id = get_current_pid_tgid();
	__s32 *error, ret;

	error = map_lookup_elem(override_tasks, &id);
	if (!error)
		return 0;

	map_delete_elem(override_tasks, &id);
	ret = *error;
	/* Let's make verifier happy and 'force' proper bounds. */
	set_if_not_errno_or_zero(ret, -1);
	return ret;
}

#endif /* __BASIC_H__ */
