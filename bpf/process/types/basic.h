// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#ifndef __BASIC_H__
#define __BASIC_H__

#include "operations.h"
#include "bpf_events.h"
#include "skb.h"
#include "sock.h"
#include "../bpf_process_event.h"
#include "bpfattr.h"
#include "perfevent.h"
#include "bpfmap.h"
#include "user_namespace.h"
#include "capabilities.h"
#include "../argfilter_maps.h"
#include "common.h"
#include "process/data_event.h"

/* Type IDs form API with user space generickprobe.go */
enum {
	filter = -2,
	nop = 0,
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
};

enum {
	FGS_SIGKILL = 9,
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

#define FLAGS_EARLY_FILTER BIT(0)

struct event_config {
	__u32 func_id;
	__s32 arg0;
	__s32 arg1;
	__s32 arg2;
	__s32 arg3;
	__s32 arg4;
	__u32 arg0m;
	__u32 arg1m;
	__u32 arg2m;
	__u32 arg3m;
	__u32 arg4m;
	__u32 t_arg0_ctx_off;
	__u32 t_arg1_ctx_off;
	__u32 t_arg2_ctx_off;
	__u32 t_arg3_ctx_off;
	__u32 t_arg4_ctx_off;
	__u32 syscall;
	__s32 argreturncopy;
	__s32 argreturn;
	/* policy id identifies the policy of this generic hook and is used to
	 * apply policies only on certain processes. A value of 0 indicates
	 * that the hook always applies and no check will be performed.
	 */
	__u32 policy_id;
	__u32 flags;
} __attribute__((packed));

#define MAX_ARGS_SIZE	 80
#define MAX_ARGS_ENTRIES 8
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
#define MAX_STRING 1024

#ifdef __MULTI_KPROBE
static inline __attribute__((always_inline)) __u32 get_index(void *ctx)
{
	return (__u32)get_attach_cookie(ctx);
}
#else
#define get_index(ctx) 0
#endif

// Filter tailcalls are {kprobe,tracepoint}/{6,7,8,9,10}
// We do one tail-call per selector, so we can have up to 5 selectors.
#define MIN_FILTER_TAILCALL 6
#define MAX_FILTER_TAILCALL 10
#define MAX_SELECTORS	    (MAX_FILTER_TAILCALL - MIN_FILTER_TAILCALL + 1)

static inline __attribute__((always_inline)) bool ty_is_nop(int ty)
{
	switch (ty) {
	case nop:
	case nop_s64_ty:
	case nop_u64_ty:
	case nop_s32_ty:
	case nop_u32_ty:
		return true;

	default:
		return false;
	}
}

static inline __attribute__((always_inline)) int return_error(int *s, int err)
{
	*s = err;
	return sizeof(int);
}

static inline __attribute__((always_inline)) char *
args_off(struct msg_generic_kprobe *e, long off)
{
	asm volatile("%[off] &= 0x3fff;\n" ::[off] "+r"(off)
		     :);
	return e->args + off;
}

/* Error writer for use when pointer *s is lost to stack and can not
 * be recoved with known bounds. We had to push this via asm to stop
 * clang from omitting some checks and applying code motion on us.
 */
static inline __attribute__((always_inline)) int
return_stack_error(char *args, int orig, int err)
{
	asm volatile("%[orig] &= 0xfff;\n"
		     "r1 = *(u64 *)%[args];\n"
		     "r1 += %[orig];\n"
		     "*(u32 *)(r1 + 0) = %[err];\n" ::[orig] "r+"(orig),
		     [args] "m+"(args), [err] "r+"(err)
		     : "r1");
	return sizeof(int);
}

static inline __attribute__((always_inline)) int
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
	asm volatile("%[size] &= 0xfff;\n" ::[size] "+r"(size)
		     :);
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

/* Unfortunately, clang really wanted to optimize this and was fairly
 * difficult to convince it otherwise. Clang tries to join the bounding
 * operations and group the memory accesses sometimes using a couple
 * registers and shuffling values through them. All this confuses the
 * verifiers especially on <5.x series. So we get the following ASM
 * blob which I find easier to read than C code that would work here.
 */
#define ASM_RCMP                                          \
	{                                                 \
		t = s1;                                   \
		asm volatile("%[n] &= 0x7f;\n"            \
			     "r0 = %[t];\n"               \
			     "r0 += %[n];\n"              \
			     "%[c] = *(u8*)(r0 + 0);\n"   \
			     : [c] "=r"(c1)               \
			     : [n] "+r"(n1), [t] "+r:"(t) \
			     : "r0");                     \
		t = s2;                                   \
		asm volatile("%[n] &= 0x7f;\n"            \
			     "r0 = %[t];\n"               \
			     "r0 += %[n];\n"              \
			     "%[c] = *(u8*)(r0 + 0);\n"   \
			     : [c] "=r"(c2)               \
			     : [n] "+r"(n2), [t] "+r"(t)  \
			     : "c2", "r0");               \
		if (c1 != c2)                             \
			goto failed;                      \
		if (n1 < 1 || n2 < 1)                     \
			goto accept;                      \
		n1--;                                     \
		n2--;                                     \
	}

#define ASM_RCMP5        \
	{                \
		ASM_RCMP \
		ASM_RCMP \
		ASM_RCMP \
		ASM_RCMP \
		ASM_RCMP \
	}

#define ASM_RCMP20        \
	{                 \
		ASM_RCMP5 \
		ASM_RCMP5 \
		ASM_RCMP5 \
		ASM_RCMP5 \
	}

#define ASM_RCMP50         \
	{                  \
		ASM_RCMP20 \
		ASM_RCMP20 \
		ASM_RCMP5  \
		ASM_RCMP5  \
	}

#define ASM_RCMP100        \
	{                  \
		ASM_RCMP50 \
		ASM_RCMP50 \
	}

/* reverse compare bytes. n1 is index of last byte in s1. Ditto n2 of s2. */
static inline __attribute__((always_inline)) int rcmpbytes(char *s1, char *s2,
							   u64 n1, u64 n2)
{
	char c1 = 0, c2 = 0, *t;

#ifdef __LARGE_BPF_PROG
	ASM_RCMP50
#else
	ASM_RCMP20
	ASM_RCMP20
#endif
accept:
	return 0;
failed:
	return -1;
}

/* compare bytes. n is number of bytes to compare. */
static inline __attribute__((always_inline)) int cmpbytes(char *s1, char *s2,
							  size_t n)
{
	int i;
#pragma unroll
	for (i = 0; i < MAX_STRING_FILTER; i++) {
		if (i >= n)
			return 0;
		if (s1[i] != s2[i])
			return -1;
	}
	return 0;
}

static inline __attribute__((always_inline)) long
copy_path(char *args, const struct path *arg)
{
	int *s = (int *)args;
	int size = 0, flags = 0;
	char *buffer;
	void *curr = &args[4];

	buffer = d_path_local(arg, &size, &flags);
	if (!buffer)
		return 0;

	asm volatile("%[size] &= 0xff;\n" ::[size] "+r"(size)
		     :);
	probe_read(curr, size, buffer);
	*s = size;
	size += 4;

	/*
	 * the format of the path is:
	 * -------------------------------
	 * | 4 bytes | N bytes | 4 bytes |
	 * | pathlen |  path   |  flags  |
	 * -------------------------------
	 * Next we set up the flags.
	 */
	asm volatile goto(
		"r1 = *(u64 *)%[pid];\n"
		"r7 = *(u32 *)%[offset];\n"
		"if r7 s< 0 goto %l[a];\n"
		"if r7 s> 1188 goto %l[a];\n"
		"r1 += r7;\n"
		"r2 = *(u32 *)%[flags];\n"
		"*(u32 *)(r1 + 0) = r2;\n"
		:
		: [pid] "m"(args), [flags] "m"(flags), [offset] "+m"(size)
		: "r0", "r1", "r2", "r7", "memory"
		: a);
a:
	size += sizeof(u32); // for the flags

	return size;
}

static inline __attribute__((always_inline)) long
copy_strings(char *args, unsigned long arg)
{
	int *s = (int *)args;
	long size;

	size = probe_read_str(&args[4], MAX_STRING, (char *)arg);
	if (size < 0) {
		return filter;
	}
	*s = size;
	// Initial 4 bytes hold string length
	return size + 4;
}

static inline __attribute__((always_inline)) long copy_skb(char *args,
							   unsigned long arg)
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

static inline __attribute__((always_inline)) long copy_sock(char *args,
							    unsigned long arg)
{
	struct sock *sk = (struct sock *)arg;
	struct sk_type *sk_event = (struct sk_type *)args;

	set_event_from_sock(sk_event, sk);

	return sizeof(struct sk_type);
}

static inline __attribute__((always_inline)) long copy_cred(char *args,
							    unsigned long arg)
{
	struct cred *cred = (struct cred *)arg;
	struct msg_capabilities *caps = (struct msg_capabilities *)args;

	probe_read(&caps->effective, sizeof(__u64), _(&cred->cap_effective));
	probe_read(&caps->inheritable, sizeof(__u64),
		   _(&cred->cap_inheritable));
	probe_read(&caps->permitted, sizeof(__u64), _(&cred->cap_permitted));

	return sizeof(struct msg_capabilities);
}

static inline __attribute__((always_inline)) long
copy_capability(char *args, unsigned long arg)
{
	int cap = (int)arg;
	struct capability_info_type *info = (struct capability_info_type *)args;

	info->pad = 0;
	info->cap = cap;

	return sizeof(struct capability_info_type);
}

#define ARGM_INDEX_MASK	 0xf
#define ARGM_RETURN_COPY BIT(4)
#define ARGM_MAX_DATA	 BIT(5)

static inline __attribute__((always_inline)) bool
hasReturnCopy(unsigned long argm)
{
	return (argm & ARGM_RETURN_COPY) != 0;
}

static inline __attribute__((always_inline)) bool
has_max_data(unsigned long argm)
{
	return (argm & ARGM_MAX_DATA) != 0;
}

static inline __attribute__((always_inline)) unsigned long
get_arg_meta(int meta, struct msg_generic_kprobe *e)
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

static inline __attribute__((always_inline)) long
__copy_char_buf(void *ctx, long off, unsigned long arg, unsigned long bytes,
		bool max_data, struct msg_generic_kprobe *e,
		struct bpf_map_def *data_heap)
{
	int *s = (int *)args_off(e, off);
	size_t rd_bytes, extra = 8;
	int err;

#ifdef __LARGE_BPF_PROG
	if (max_data && data_heap) {
		/* The max_data flag is enabled, the first int value indicates
		 * if we use (1) data events or not (0).
		 */
		if (bytes >= 0x1000) {
			s[0] = 1;
			return data_event_bytes(ctx,
						(struct data_event_desc *)&s[1],
						arg, bytes, data_heap) +
			       4;
		}
		s[0] = 0;
		s = (int *)args_off(e, off + 4);
		extra += 4;
	}
#endif // __LARGE_BPF_PROG

	/* Bound bytes <4095 to ensure bytes does not read past end of buffer */
	rd_bytes = bytes < 0x1000 ? bytes : 0xfff;
	asm volatile("%[rd_bytes] &= 0xfff;\n" ::[rd_bytes] "+r"(rd_bytes)
		     :);
	err = probe_read(&s[2], rd_bytes, (char *)arg);
	if (err < 0)
		return return_error(s, char_buf_pagefault);
	s[0] = (int)bytes;
	s[1] = (int)rd_bytes;
	return rd_bytes + extra;
}

static inline __attribute__((always_inline)) long
copy_char_buf(void *ctx, long off, unsigned long arg, int argm,
	      struct msg_generic_kprobe *e,
	      struct bpf_map_def *data_heap)
{
	int *s = (int *)args_off(e, off);
	unsigned long meta;
	size_t bytes = 0;

	if (hasReturnCopy(argm)) {
		u64 tid = retprobe_map_get_key(ctx);
		retprobe_map_set(e->id, tid, e->common.ktime, arg);
		return return_error(s, char_buf_saved_for_retprobe);
	}
	meta = get_arg_meta(argm, e);
	probe_read(&bytes, sizeof(bytes), &meta);
	return __copy_char_buf(ctx, off, arg, bytes, has_max_data(argm), e, data_heap);
}

static inline __attribute__((always_inline)) long
filter_char_buf(struct selector_arg_filter *filter, char *args, int value_off)
{
	char *value = (char *)&filter->value;
	long i, j = 0;

#pragma unroll
	for (i = 0; i < MAX_MATCH_STRING_VALUES; i++) {
		__u32 length;
		int err, a, postoff = 0;

		/* filter->vallen is pulled from user input so we also need to
		 * ensure its bounded.
		 */
		asm volatile("%[j] &= 0xff;\n" ::[j] "+r"(j)
			     :);
		length = *(__u32 *)&value[j];
		asm volatile("%[length] &= 0xff;\n" ::[length] "+r"(length)
			     :);
		// arg length is 4 bytes before the value data
		a = *(int *)&args[value_off - 4];
		if (filter->op == op_filter_eq) {
			if (length != a)
				goto skip_string;
		} else if (filter->op == op_filter_str_postfix) {
			postoff = a - length;
			asm volatile("%[postoff] &= 0x3f;\n" ::[postoff] "+r"(
					     postoff)
				     :);
		}

		/* This is redundant, but seems we lost 'j' bounds from
		 * above so at the moment its necessary until we improve
		 * compiler.
		 */
		asm volatile("%[j] &= 0xff;\n" ::[j] "+r"(j)
			     :);
		err = cmpbytes(&value[j + 4], &args[value_off + postoff], length);
		if (!err)
			return 1;
	skip_string:
		j += length + 4;
		if (j + 8 >= filter->vallen)
			break;
	}
	return 0;
}

static inline __attribute__((always_inline)) long
__filter_file_buf(char *value, char *args, __u32 op)
{
	int err;
	__u64 v, a;

	/* filter->vallen is pulled from user input so we also need to
	 * ensure its bounded.
	 */
	v = (unsigned int)value[0];
	a = (unsigned int)args[0];
	/* There are cases where file pointer may not contain a path.
	 * An example is using an unnamed pipe. This is not a match.
	 */
	if (a == 0)
		goto skip_string;
	if (op == op_filter_eq) {
		if (v != a)
			goto skip_string;
	} else if (op == op_filter_str_prefix) {
		if (a < v)
			goto skip_string;
	} else if (op == op_filter_str_postfix) {
		err = rcmpbytes(&value[4], &args[4], v - 1, a - 1);
		if (!err)
			return 0;
		goto skip_string;
	}
	err = cmpbytes(&value[4], &args[4], v);
	if (!err)
		return 0;
skip_string:
	return v + 4;
}

/* filter_file_buf: runs a comparison between the file path in args against the
 * filter file path. For 'equal' and 'prefix' operators we compare the file path
 * and the filter file path in the normal order. For the 'postfix' operator we do
 * a reverse search.
 */
static inline __attribute__((always_inline)) long
filter_file_buf(struct selector_arg_filter *filter, char *args)
{
	char *value = (char *)&filter->value;
	int i, next;

#ifndef __LARGE_BPF_PROG
#pragma unroll
#endif
	for (i = 0; i < MAX_MATCH_FILE_VALUES; ++i) {
		next = __filter_file_buf(value, args, filter->op);
		if (!next)
			return 1;
		else if (next + 8 > filter->vallen)
			return 0;
		value += (next & 0x7f);
	}

	return 0;
}

static inline __attribute__((always_inline)) long
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

static inline __attribute__((always_inline)) long
copy_char_iovec(void *ctx, long off, unsigned long arg, int argm,
		struct msg_generic_kprobe *e)
{
	int *s = (int *)args_off(e, off);
	unsigned long meta;

	meta = get_arg_meta(argm, e);

	if (hasReturnCopy(argm)) {
		u64 tid = retprobe_map_get_key(ctx);
		retprobe_map_set_iovec(e->id, tid, e->common.ktime, arg, meta);
		return return_error(s, char_buf_saved_for_retprobe);
	}
	return __copy_char_iovec(off, arg, meta, 0, e);
}

static inline __attribute__((always_inline)) long
copy_bpf_attr(char *args, unsigned long arg)
{
	union bpf_attr *ba = (union bpf_attr *)arg;
	struct bpf_info_type *bpf_info = (struct bpf_info_type *)args;

	/* struct values */
	probe_read(&bpf_info->prog_type, sizeof(__u32), _(&ba->prog_type));
	probe_read(&bpf_info->insn_cnt, sizeof(__u32), _(&ba->insn_cnt));
	probe_read(&bpf_info->prog_name, BPF_OBJ_NAME_LEN, _(&ba->prog_name));

	return sizeof(struct bpf_info_type);
}

static inline __attribute__((always_inline)) long
copy_perf_event(char *args, unsigned long arg)
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

static inline __attribute__((always_inline)) long
copy_bpf_map(char *args, unsigned long arg)
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

// filter on values provided in the selector itself
static inline __attribute__((always_inline)) long
filter_64ty_selector_val(struct selector_arg_filter *filter, char *args)
{
	__u64 *v = (__u64 *)&filter->value;
	int i, j = 0;

#pragma unroll
	for (i = 0; i < MAX_MATCH_VALUES; i++) {
		__u64 w = v[i];
		bool res;

		switch (filter->op) {
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
		default:
			break;
		}
		j += 8;
		if (j + 8 >= filter->vallen)
			break;
	}
	return 0;
}

// use the selector value to determine a hash map, and do a lookup to determine whether the argument
// is in the defined set.
static inline __attribute__((always_inline)) long
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

static inline __attribute__((always_inline)) long
copy_user_namespace(char *args, unsigned long arg)
{
	struct user_namespace *ns = (struct user_namespace *)arg;
	struct user_namespace_info_type *u_ns_info =
		(struct user_namespace_info_type *)args;

	probe_read(&u_ns_info->level, sizeof(__s32), _(&ns->level));
	probe_read(&u_ns_info->owner, sizeof(__u32), _(&ns->owner));
	probe_read(&u_ns_info->group, sizeof(__u32), _(&ns->group));
	probe_read(&u_ns_info->ns_inum, sizeof(__u32), _(&ns->ns.inum));

	return sizeof(struct user_namespace_info_type);
}

static inline __attribute__((always_inline)) long
filter_64ty(struct selector_arg_filter *filter, char *args)
{
	switch (filter->op) {
	case op_filter_eq:
	case op_filter_neq:
	case op_filter_mask:
		return filter_64ty_selector_val(filter, args);
	case op_filter_inmap:
	case op_filter_notinmap:
		return filter_64ty_map(filter, args);
	}

	return 0;
}

static inline __attribute__((always_inline)) long
filter_32ty_selector_val(struct selector_arg_filter *filter, char *args)
{
	__u32 *v = (__u32 *)&filter->value;
	int i, j = 0;

#pragma unroll
	for (i = 0; i < MAX_MATCH_VALUES; i++) {
		__u32 w = v[i];
		bool res;

		switch (filter->op) {
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
static inline __attribute__((always_inline)) long
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
		return !!pass;
	case op_filter_notinmap:
		return !pass;
	}
	return 0;
}

static inline __attribute__((always_inline)) long
filter_32ty(struct selector_arg_filter *filter, char *args)
{
	switch (filter->op) {
	case op_filter_eq:
	case op_filter_neq:
	case op_filter_mask:
		return filter_32ty_selector_val(filter, args);
	case op_filter_inmap:
	case op_filter_notinmap:
		return filter_32ty_map(filter, args);
	}

	return 0;
}

static inline __attribute__((always_inline)) size_t type_to_min_size(int type,
								     int argm)
{
	switch (type) {
	case fd_ty:
	case file_ty:
	case path_ty:
	case string_type:
		return MAX_STRING;
	case int_type:
	case s32_ty:
	case u32_ty:
		return 4;
	case skb_type:
		return sizeof(struct skb_type);
	case sock_type:
		return sizeof(struct sk_type);
	case cred_type:
		return sizeof(struct msg_capabilities);
	case size_type:
	case s64_ty:
	case u64_ty:
		return 8;
	case char_buf:
	case char_iovec:
		return 4;
	case const_buf_type:
		return argm;
	case bpf_attr_type:
		return sizeof(struct bpf_info_type);
	case perf_event_type:
		return sizeof(struct perf_event_info_type);
	case bpf_map_type:
		return sizeof(struct bpf_map_info_type);
	case user_namespace_type:
		return sizeof(struct user_namespace_info_type);
	case capability_type:
		return sizeof(struct capability_info_type);
	// nop or something else we do not process here
	default:
		return 0;
	}
}

#define INDEX_MASK 0x3ff

/*
 * For matchBinaries we use two maps:
 * 1. names_map: global (for all sensors) keeps a mapping from names -> ids
 * 2. sel_names_map: per-sensor: keeps a mapping from selector_id -> id -> selector val
 *
 * For each selector we have a separate inner map. We choose the appropriate
 * inner map based on the selector ID.
 *
 * At exec time, we check names_map and set ->binary in execve_map equal to
 * the id stored in names_map. Assuming the binary name exists in the map,
 * otherwise binary is 0.
 *
 * When we check the selectors, use ->binary to index sel_names_map and decide
 * whether the selector matches or not.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(max_entries, MAX_SELECTORS);
	__uint(key_size, sizeof(u32)); /* selector id */
	__array(
		values, struct {
			__uint(type, BPF_MAP_TYPE_HASH);
			__uint(max_entries, 256);
			__type(key, __u32);
			__type(value, __u32);
		});
} sel_names_map SEC(".maps");

static inline __attribute__((always_inline)) int match_binaries(void *sel_names, __u32 selidx)
{
	void *binaries_map;
	struct execve_map_value *execve;
	__u32 *op, max = 0xffffffff; // UINT32_MAX
	__u32 ppid, bin_key, *bin_val;
	bool walker = 0;

	// if binaries_map is NULL for the specific selidx, this
	// means that the specific selector does not contain any
	// matchBinaries actions. So we just proceed.
	binaries_map = map_lookup_elem(sel_names, &selidx);
	if (binaries_map) {
		op = map_lookup_elem(binaries_map, &max);
		if (op) {
			execve = event_find_curr(&ppid, &walker);
			if (!execve)
				return 0;

			bin_key = execve->binary;
			bin_val = map_lookup_elem(binaries_map, &bin_key);

			/*
			 * The following things may happen:
			 * binary is not part of names_map, execve_map->binary will be `0` and `bin_val` will always be `0`
			 * binary is part of `names_map`:
			 *  if binary is not part of this selector, bin_val will be`0`
			 *  if binary is part of this selector: `bin_val will be `!0`
			 */
			if (*op == op_filter_in) {
				if (!bin_val)
					return 0;
			} else if (*op == op_filter_notin) {
				if (bin_val)
					return 0;
			}
		}
	}

	return 1;
}

static inline __attribute__((always_inline)) int
generic_process_filter_binary(struct event_config *config)
{
	/* single flag bit at the moment (FLAGS_EARLY_FILTER) */
	if (config->flags & FLAGS_EARLY_FILTER)
		return match_binaries(&sel_names_map, 0);
	return 1;
}

static inline __attribute__((always_inline)) int
selector_arg_offset(__u8 *f, struct msg_generic_kprobe *e, __u32 selidx,
		    bool early_binary_filter)
{
	struct selector_arg_filters *filters;
	struct selector_arg_filter *filter;
	long seloff, argoff, argsoff, pass = 1, margsoff;
	__u32 i = 0, index;
	char *args;

	seloff = 4; /* start of the relative offsets */
	seloff += (selidx * 4); /* relative offset for this selector */

	/* selector section offset by reading the relative offset in the array */
	seloff += *(__u32 *)((__u64)f + (seloff & INDEX_MASK));

	/* skip the selector size field */
	seloff += 4;
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

	// check for match binary actions
	if (!early_binary_filter && !match_binaries(&sel_names_map, selidx))
		return 0;

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
		asm volatile("%[argsoff] &= 0x3ff;\n" ::[argsoff] "+r"(argsoff)
			     :);

		if (argsoff <= 0)
			return pass ? seloff : 0;

		margsoff = (seloff + argsoff) & INDEX_MASK;
		filter = (struct selector_arg_filter *)&f[margsoff];

		index = filter->index;
		if (index > 5)
			return 0;

		asm volatile("%[index] &= 0x7;\n" ::[index] "+r"(index)
			     :);
		argoff = e->argsoff[index];
		asm volatile("%[argoff] &= 0x7ff;\n" ::[argoff] "+r"(argoff)
			     :);
		args = &e->args[argoff];

		switch (filter->type) {
		case fd_ty:
			/* Advance args past fd */
			args += 4;
		case file_ty:
		case path_ty:
			pass &= filter_file_buf(filter, args);
			break;
		case string_type:
			/* for strings, we just encode the length */
			pass &= filter_char_buf(filter, args, 4);
			break;
		case char_buf:
			/* for buffers, we just encode the expected length and the
			 * length that was actually read (see: __copy_char_buf)
			 */
			pass &= filter_char_buf(filter, args, 8);
			break;
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
		default:
			break;
		}
	}
	return pass ? seloff : 0;
}

static inline __attribute__((always_inline)) int filter_args_reject(u64 id)
{
	u64 tid = get_current_pid_tgid();
	retprobe_map_clear(id, tid);
	return 0;
}

static inline __attribute__((always_inline)) int
filter_args(struct msg_generic_kprobe *e, int index, void *filter_map,
	    bool early_binary_filter)
{
	__u8 *f;

	/* No filters and no selectors so just accepts */
	f = map_lookup_elem(filter_map, &e->idx);
	if (!f) {
		return 1;
	}

	/* No selectors, accept by default */
	if (!e->sel.active[SELECTORS_ACTIVE])
		return 1;

	/* We ran process filters early as a prefilter to drop unrelated
	 * events early. Now we need to ensure that active pid sselectors
	 * have their arg filters run.
	 */
	if (index > SELECTORS_ACTIVE)
		return filter_args_reject(e->id);

	if (e->sel.active[index]) {
		int pass = selector_arg_offset(f, e, index, early_binary_filter);
		if (pass)
			return pass;
	}
	return 0;
}

struct fdinstall_key {
	__u64 tid;
	__u32 fd;
	__u32 pad;
};

struct fdinstall_value {
	char file[264]; // 256B paths + 4B length + 4B flags
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 32000);
	__type(key, struct fdinstall_key);
	__type(value, struct fdinstall_value);
} fdinstall_map SEC(".maps");

static inline __attribute__((always_inline)) int
installfd(struct msg_generic_kprobe *e, int fd, int name, bool follow)
{
	struct fdinstall_value val = { 0 };
	struct fdinstall_key key = { 0 };
	long fdoff, nameoff;
	int err = 0;

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
		asm volatile("%[size] &= 0xff;\n"
			     : [size] "+r"(size)
			     :);

		probe_read(&val.file[0], size + 4 /* size */ + 4 /* flags */,
			   &e->args[nameoff]);
		map_update_elem(&fdinstall_map, &key, &val, BPF_ANY);
	} else {
		err = map_delete_elem(&fdinstall_map, &key);
	}
	return err;
}

static inline __attribute__((always_inline)) int
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
static inline __attribute__((always_inline)) void
do_action_signal(int signal)
{
	send_signal(signal);
}
#else
#define do_action_signal(signal)
#endif /* __LARGE_BPF_PROG */

static inline __attribute__((always_inline)) __u32
do_action(__u32 i, struct msg_generic_kprobe *e,
	  struct selector_action *actions, struct bpf_map_def *override_tasks)
{
	int signal __maybe_unused = FGS_SIGKILL;
	int action = actions->act[i];
	__s32 error, *error_p;
	int fdi, namei;
	int newfdi, oldfdi;
	int err = 0;
	__u64 id;

	switch (action) {
	case ACTION_UNFOLLOWFD:
	case ACTION_FOLLOWFD:
		fdi = actions->act[++i];
		namei = actions->act[++i];
		err = installfd(e, fdi, namei, action == ACTION_FOLLOWFD);
		break;
	case ACTION_COPYFD:
		oldfdi = actions->act[++i];
		newfdi = actions->act[++i];
		err = copyfd(e, oldfdi, newfdi);
		break;
	case ACTION_SIGNAL:
		signal = actions->act[++i];
	case ACTION_SIGKILL:
		do_action_signal(signal);
		break;
	case ACTION_OVERRIDE:
		error = actions->act[++i];
		id = get_current_pid_tgid();

		if (!override_tasks)
			break;
		/*
		 * TODO: this should not happen, it means that the override
		 * program was not executed for some reason, we should do
		 * warning in here
		 */
		error_p = map_lookup_elem(override_tasks, &id);
		if (error_p)
			*error_p = error;
		else
			map_update_elem(override_tasks, &id, &error, BPF_ANY);
		break;
	case ACTION_GETURL:
	case ACTION_DNSLOOKUP:
		/* Set the URL or DNS action */
		e->action_arg_id = actions->act[++i];
		break;
	default:
		break;
	}
	if (!err) {
		e->action = action;
		return ++i;
	}
	return 0;
}

static inline __attribute__((always_inline)) bool
has_action(struct selector_action *actions, __u32 idx)
{
	__u32 offset = idx * sizeof(__u32) + sizeof(*actions);

	return offset < actions->actionlen;
}

/* Currently supporting 2 actions for selector. */
static inline __attribute__((always_inline)) bool
do_actions(struct msg_generic_kprobe *e, struct selector_action *actions,
	   struct bpf_map_def *override_tasks)
{
	bool nopost = false;
	__u32 l, i = 0;

#ifndef __LARGE_BPF_PROG
#pragma unroll
#endif
	for (l = 0; l < MAX_ACTIONS; l++) {
		if (!has_action(actions, i))
			return !nopost;

		i = do_action(i, e, actions, override_tasks);
		if (!i)
			return false;

		nopost |= actions->act[0] == ACTION_NOPOST;
	}

	return !nopost;
}

static inline __attribute__((always_inline)) long
filter_read_arg(void *ctx, int index, struct bpf_map_def *heap,
		struct bpf_map_def *filter, struct bpf_map_def *tailcalls,
		struct bpf_map_def *config_map)
{
	struct msg_generic_kprobe *e;
	struct event_config *config;
	int pass, zero = 0;

	e = map_lookup_elem(heap, &zero);
	if (!e)
		return 0;
	config = map_lookup_elem(config_map, &e->idx);
	if (!config)
		return 0;
	pass = filter_args(e, index, filter, config->flags & FLAGS_EARLY_FILTER);
	if (!pass) {
		index++;
		if (index <= MAX_SELECTORS && e->sel.active[index])
			tail_call(ctx, tailcalls, MIN_FILTER_TAILCALL + index);
		// reject if we did not attempt to tailcall, or if tailcall failed.
		return filter_args_reject(e->id);
	}

	// If pass >1 then we need to consult the selector actions
	// otherwise pass==1 indicates using default action.
	if (pass > 1) {
		e->pass = pass;
		tail_call(ctx, tailcalls, 11);
	}

	tail_call(ctx, tailcalls, 12);
	return 1;
}

static inline __attribute__((always_inline)) long
generic_actions(void *ctx, struct bpf_map_def *heap,
		struct bpf_map_def *filter,
		struct bpf_map_def *tailcalls,
		struct bpf_map_def *override_tasks)
{
	struct selector_arg_filters *arg;
	struct selector_action *actions;
	struct msg_generic_kprobe *e;
	int actoff, pass, zero = 0;
	bool postit;
	__u8 *f;

	e = map_lookup_elem(heap, &zero);
	if (!e)
		return 0;

	pass = e->pass;
	if (pass <= 1)
		return 0;

	f = map_lookup_elem(filter, &e->idx);
	if (!f)
		return 0;

	asm volatile("%[pass] &= 0x7ff;\n"
		     : [pass] "+r"(pass)
		     :);
	arg = (struct selector_arg_filters *)&f[pass];

	actoff = pass + arg->arglen;
	asm volatile("%[actoff] &= 0x7ff;\n"
		     : [actoff] "+r"(actoff)
		     :);
	actions = (struct selector_action *)&f[actoff];

	postit = do_actions(e, actions, override_tasks);
	if (postit)
		tail_call(ctx, tailcalls, 12);
	return 1;
}

static inline __attribute__((always_inline)) long
generic_output(void *ctx, struct bpf_map_def *heap)
{
	struct msg_generic_kprobe *e;
	int zero = 0;
	size_t total;

	e = map_lookup_elem(heap, &zero);
	if (!e)
		return 0;

#ifdef __NS_CHANGES_FILTER
	/* update the namespaces if we matched a change on that */
	if (e->sel.match_ns) {
		__u32 pid = (get_current_pid_tgid() >> 32);
		struct task_struct *task =
			(struct task_struct *)get_current_task();
		struct execve_map_value *enter = execve_map_get_noinit(
			pid); // we don't want to init that if it does not exist
		if (enter)
			get_namespaces(&(enter->ns), task);
	}
#endif
#ifdef __CAP_CHANGES_FILTER
	/* update the capabilities if we matched a change on that */
	if (e->sel.match_cap) {
		__u32 pid = (get_current_pid_tgid() >> 32);
		struct task_struct *task =
			(struct task_struct *)get_current_task();
		struct execve_map_value *enter = execve_map_get_noinit(
			pid); // we don't want to init that if it does not exist
		if (enter)
			get_current_subj_caps(&enter->caps, task);
	}
#endif

	total = e->common.size + generic_kprobe_common_size();
	/* Code movement from clang forces us to inline bounds checks here */
	asm volatile("%[total] &= 0x7fff;\n"
		     "if %[total] < 9000 goto +1\n;"
		     "%[total] = 9000;\n"
		     :
		     : [total] "+r"(total)
		     :);
	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, e, total);
	return 1;
}

/**
 * Read a generic argument
 *
 * @args: destination buffer for the generic argument
 * @type: type of the argument
 * @off: offset of the argument within @args
 * @arg: argument location (generally, address of the argument)
 * @argm: argument metadata. The meaning of this depends on the @type. Some
 *        types use a -1 to designate saving @arg into the retprobe map
 * @filter_map:
 *
 * Returns the size of data appended to @args.
 */
static inline __attribute__((always_inline)) long
read_call_arg(void *ctx, struct msg_generic_kprobe *e, int index, int type,
	      long orig_off, unsigned long arg, int argm,
	      struct bpf_map_def *data_heap)
{
	size_t min_size = type_to_min_size(type, argm);
	char *args = e->args;
	long size = -1;
	const struct path *path_arg = 0;

	if (orig_off >= 16383 - min_size) {
		return 0;
	}
	args = args_off(e, orig_off);

	/* Cache args offset for filter use later */
	e->argsoff[index] = orig_off;

	switch (type) {
	case file_ty: {
		struct file *file;
		probe_read(&file, sizeof(file), &arg);
		path_arg = _(&file->f_path);
	}
		// fallthrough to copy_path
	case path_ty: {
		if (!path_arg)
			probe_read(&path_arg, sizeof(path_arg), &arg);
		size = copy_path(args, path_arg);
		break;
	}
	case fd_ty: {
		struct fdinstall_key key = { 0 };
		struct fdinstall_value *val;
		__u32 fd;

		key.tid = get_current_pid_tgid() >> 32;
		probe_read(&fd, sizeof(__u32), &arg);
		key.fd = fd;

		val = map_lookup_elem(&fdinstall_map, &key);
		if (val) {
			__u32 bytes = (__u32)val->file[0];

			probe_read(&args[0], sizeof(__u32), &fd);
			asm volatile("%[bytes] &= 0xff;\n"
				     : [bytes] "+r"(bytes)
				     :);
			probe_read(&args[4], bytes + 4, (char *)&val->file[0]);
			size = bytes + 4 + 4;

			// flags
			probe_read(&args[size], 4,
				   (char *)&val->file[size - 4]);
			size += 4;
		} else {
			/* If filter specification is fd type then we
			 * expect the fd has been previously followed
			 * otherwise drop the event.
			 */
			return -1;
		}
	} break;
	case filename_ty: {
		struct filename *file;
		probe_read(&file, sizeof(file), &arg);
		probe_read(&arg, sizeof(arg), &file->name);
	}
		// fallthrough to copy_string
	case string_type:
		size = copy_strings(args, arg);
		break;
	case size_type:
	case s64_ty:
	case u64_ty:
		probe_read(args, sizeof(__u64), &arg);
		size = sizeof(__u64);
		break;
	/* Consolidate all the types to save instructions */
	case int_type:
	case s32_ty:
	case u32_ty:
		probe_read(args, sizeof(__u32), &arg);
		size = sizeof(__u32);
		break;
	case skb_type:
		size = copy_skb(args, arg);
		break;
	case sock_type:
		size = copy_sock(args, arg);
		break;
	case cred_type:
		size = copy_cred(args, arg);
		break;
	case char_buf:
		size = copy_char_buf(ctx, orig_off, arg, argm, e, data_heap);
		break;
	case char_iovec:
		size = copy_char_iovec(ctx, orig_off, arg, argm, e);
		break;
	case const_buf_type: {
		// bound size to 1023 to help the verifier out
		size = argm & 0x03ff;
		probe_read(args, size, (char *)arg);
		break;
	}
	case bpf_attr_type: {
		size = copy_bpf_attr(args, arg);
		break;
	}
	case perf_event_type: {
		size = copy_perf_event(args, arg);
		break;
	}
	case bpf_map_type: {
		size = copy_bpf_map(args, arg);
		break;
	}
	case user_namespace_type: {
		size = copy_user_namespace(args, arg);
		break;
	}
	case capability_type: {
		size = copy_capability(args, arg);
		break;
	}
	default:
		size = 0;
		break;
	}
	return size;
}

#endif /* __BASIC_H__ */
