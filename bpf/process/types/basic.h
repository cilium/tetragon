// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#include "operations.h"
#include "bpf_events.h"
#include "skb.h"
#include "sock.h"
#include "../bpf_process_event.h"

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
};

enum {
	FGS_SIGKILL = 9,
};

struct selector_action {
	__u32 actionlen;
	__u32 act[];
};

struct selector_binary_filter {
	__u32 arglen;
	__u32 op;
	__u32 index[4];
};

struct selector_arg_filter {
	__u32 arglen;
	__u32 index;
	__u32 op;
	__u32 vallen;
	__u32 type;
	__u8 value;
} __attribute__((packed));

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
	__u32 sigkill;
	__u32 syscall;
	__s32 argreturncopy;
	__s32 argreturn;
} __attribute__((packed));

#define MAX_ARGS_SIZE	 80
#define MAX_ARGS_ENTRIES 8
#define MAX_MATCH_VALUES 4
/* String parsing consumes instructions so this adds an additional
 * knob to tune how many instructions we should spend parsing
 * strings.
 */
#define MAX_MATCH_STRING_VALUES 2

/* Constants bounding printers if these change or buffer size changes then
 * we will need to resize. TBD would be to size these at compile time using
 * buffer size information.
 */
#define MAX_STRING 1024

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
	asm volatile("%[off] &= 0x3fff;\n" ::[off] "+r"(off) :);
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
	asm volatile("%[size] &= 0xfff;\n" ::[size] "+r"(size) :);
	err = probe_read(args_off(e, off), size, (char *)iov.iov_base);
	if (err < 0)
		return char_buf_pagefault;
	return size;
}

// for loop can not be unrolled which is needed for 4.19 kernels :(
#define PARSE_IOVEC_ENTRY                                                      \
	{                                                                      \
		int c;                                                         \
		/* embedding this in the loop counter breaks verifier */       \
		if (i >= cnt)                                                  \
			goto char_iovec_done;                                  \
		c = parse_iovec_array(off, arg, i, max, e);                    \
		if (c < 0) {                                                   \
			char *args = args_off(e, off_orig);                    \
			return return_stack_error(args, 0, c);                 \
		}                                                              \
		size += c;                                                     \
		if (max) {                                                     \
			max -= c;                                              \
			if (!max)                                              \
				goto char_iovec_done;                          \
		}                                                              \
		c &= 0x7fff;                                                   \
		off += c;                                                      \
		i++;                                                           \
	}

// We parse a max iovec entries and any more can be detected in db
#define PARSE_IOVEC_ENTRIES                                                    \
	{                                                                      \
		PARSE_IOVEC_ENTRY                                              \
		PARSE_IOVEC_ENTRY                                              \
		PARSE_IOVEC_ENTRY                                              \
		PARSE_IOVEC_ENTRY                                              \
		PARSE_IOVEC_ENTRY                                              \
		PARSE_IOVEC_ENTRY                                              \
		PARSE_IOVEC_ENTRY                                              \
	}

#define MAX_STRING_FILTER	128
#define MAX_STRING_FILTER_SMALL 32

/* Unfortunately, clang really wanted to optimize this and was fairly
 * difficult to convince it otherwise. Clang tries to join the bounding
 * operations and group the memory accesses sometimes using a couple
 * registers and shuffling values through them. All this confuses the
 * verifiers especially on <5.x series. So we get the following ASM
 * blob which I find easier to read than C code that would work here.
 */
#define ASM_RCMP                                                               \
	{                                                                      \
		t = s1;                                                        \
		asm volatile("%[n] &= 0x7f;\n"                                 \
			     "r0 = %[t];\n"                                    \
			     "r0 += %[n];\n"                                   \
			     "%[c] = *(u8*)(r0 + 0);\n"                        \
			     : [c] "=r"(c1)                                    \
			     : [n] "+r"(n1), [t] "+r:"(t)                      \
			     : "r0");                                          \
		t = s2;                                                        \
		asm volatile("%[n] &= 0x7f;\n"                                 \
			     "r0 = %[t];\n"                                    \
			     "r0 += %[n];\n"                                   \
			     "%[c] = *(u8*)(r0 + 0);\n"                        \
			     : [c] "=r"(c2)                                    \
			     : [n] "+r"(n2), [t] "+r"(t)                       \
			     : "c2", "r0");                                    \
		if (c1 != c2)                                                  \
			goto failed;                                           \
		n1--;                                                          \
		n2--;                                                          \
		if (n1 < 1 || n2 < 1)                                          \
			goto accept;                                           \
	}

#define ASM_RCMP5                                                              \
	{                                                                      \
		ASM_RCMP                                                       \
		ASM_RCMP                                                       \
		ASM_RCMP                                                       \
		ASM_RCMP                                                       \
		ASM_RCMP                                                       \
	}

#define ASM_RCMP20                                                             \
	{                                                                      \
		ASM_RCMP5                                                      \
		ASM_RCMP5                                                      \
		ASM_RCMP5                                                      \
		ASM_RCMP5                                                      \
	}

#define ASM_RCMP50                                                             \
	{                                                                      \
		ASM_RCMP20                                                     \
		ASM_RCMP20                                                     \
		ASM_RCMP5                                                      \
	}

#define ASM_RCMP100                                                            \
	{                                                                      \
		ASM_RCMP50                                                     \
		ASM_RCMP50                                                     \
	}

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

static inline __attribute__((always_inline)) int cmpbytes(char *s1, char *s2,
							  size_t n)
{
	int i;
#pragma unroll
	for (i = 0; i < MAX_STRING_FILTER; i++) {
		if (i < n && s1[i] != s2[i])
			return -1;
	}
	return 0;
}

static inline __attribute__((always_inline)) int
cmpbytes_small(char *s1, char *s2, size_t n)
{
	int i;
#pragma unroll
	for (i = 0; i < MAX_STRING_FILTER_SMALL; i++) {
		if (i < n && s1[i] != s2[i])
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
	int zero = 0;
	void *curr = &args[4];

	buffer = map_lookup_elem(&buffer_heap_map, &zero);
	if (!buffer)
		return 0;

	size = 256;
	buffer = __d_path_local(arg, buffer, &size, &flags);
	if (!buffer)
		return 0;
	if (size > 0)
		size = 256 - size;

	asm volatile("%[size] &= 0xff;\n" ::[size] "+r"(size) :);
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

#define ARGM_INDEX_MASK	 ((1 << 4) - 1)
#define ARGM_RETURN_COPY (1 << 4)

static inline __attribute__((always_inline)) bool
hasReturnCopy(unsigned long argm)
{
	return (argm & ARGM_RETURN_COPY) != 0;
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
__copy_char_buf(long off, unsigned long arg, unsigned long bytes,
		struct msg_generic_kprobe *e)
{
	int *s = (int *)args_off(e, off);
	size_t rd_bytes;
	int err;

	/* Bound bytes <4095 to ensure bytes does not read past end of buffer */
	rd_bytes = bytes;
	rd_bytes &= 0xfff;
	err = probe_read(&s[2], rd_bytes, (char *)arg);
	if (err < 0)
		return return_error(s, char_buf_pagefault);
	s[0] = (int)bytes;
	s[1] = (int)rd_bytes;
	return rd_bytes + 8;
}

static inline __attribute__((always_inline)) long
copy_char_buf(void *ctx, long off, unsigned long arg, int argm,
	      struct msg_generic_kprobe *e)
{
	int *s = (int *)args_off(e, off);
	unsigned long meta;
	size_t bytes = 0;

	if (hasReturnCopy(argm)) {
		u64 tid = retprobe_map_get_key(ctx);
		retprobe_map_set(tid, arg);
		return return_error(s, char_buf_saved_for_retprobe);
	}
	meta = get_arg_meta(argm, e);
	probe_read(&bytes, sizeof(bytes), &meta);
	return __copy_char_buf(off, arg, bytes, e);
}

static inline __attribute__((always_inline)) long
filter_char_buf(struct selector_arg_filter *filter, char *args)
{
	char *value = (char *)&filter->value;
	long i, j = 0;

#pragma unroll
	for (i = 0; i < MAX_MATCH_STRING_VALUES; i++) {
		__u32 length;
		int err, v, a, postoff = 0;

		/* filter->vallen is pulled from user input so we also need to
		 * ensure its bounded.
		 */
		asm volatile("%[j] &= 0xff;\n" ::[j] "+r"(j) :);
		length = *(__u32 *)&value[j];
		asm volatile("%[length] &= 0x3f;\n" ::[length] "+r"(length) :);
		v = (int)value[j];
		a = (int)args[0];
		if (filter->op == op_filter_eq) {
			if (v != a)
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
		asm volatile("%[j] &= 0xff;\n" ::[j] "+r"(j) :);
		err = cmpbytes(&value[j + 4], &args[4 + postoff], length);
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
	if (op == op_filter_eq) {
		if (v != a)
			goto skip_string;
	} else if (op == op_filter_str_prefix) {
		if (a < v)
			goto skip_string;
	} else if (op == op_filter_str_postfix) {
#ifdef __LARGE_BPF_PROG
		err = cmpbytes(&value[4], &args[4], v - 1);
#else
		err = cmpbytes_small(&value[4], &args[4], v - 1);
#endif
		if (!err)
			return 0;
	}
	err = rcmpbytes(&value[4], &args[4], v - 1, a - 1);
	if (!err)
		return 0;
skip_string:
	return v + 4;
}

/* filter_file_buf: runs a comparison between the file path in args against the
 * filter file path. This is slightly different from a string compare because
 * files are stored in reverse order. We could swap them in kernel but this is
 * problematic as well from a complexity angle. At the moment it seems easiest
 * to simply special case filepaths and do a reverse search over them. Notice
 * for 'equals' operatore either direction would work. But for prefix and
 * postfix mappings direction matters.
 */
static inline __attribute__((always_inline)) long
filter_file_buf(struct selector_arg_filter *filter, char *args)
{
	char *value = (char *)&filter->value;
	int next;

	next = __filter_file_buf(value, args, filter->op);
	if (!next)
		return 1;
	else if (next + 8 > filter->vallen)
		return 0;
	value += (next & 0x7f);
	next = __filter_file_buf(value, args, filter->op);
	if (!next)
		return 1;
	return 0;
}

static inline __attribute__((always_inline)) long
__copy_char_iovec(long off, unsigned long arg, unsigned long meta,
		  unsigned long max, struct msg_generic_kprobe *e)
{
	long size, off_orig = off;
	int err, i = 0, cnt;
	int *s;

	err = probe_read(&cnt, sizeof(cnt), &meta);
	if (err < 0) {
		char *args = args_off(e, off_orig);
		return return_stack_error(args, 0, char_buf_pagefault);
	}

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
		retprobe_map_set_iovec(tid, arg, meta);
		return return_error(s, char_buf_saved_for_retprobe);
	}
	return __copy_char_iovec(off, arg, meta, 0, e);
}

static inline __attribute__((always_inline)) long
filter_64ty(struct selector_arg_filter *filter, char *args)
{
	__u64 *v = (__u64 *)&filter->value;
	int i, j = 0;

#pragma unroll
	for (i = 0; i < MAX_MATCH_VALUES; i++) {
		__u64 w = v[i];
		bool res = (*(u64 *)args == w);

		if (filter->op == op_filter_eq && res)
			return 1;
		if (filter->op == op_filter_neq && !res)
			return 1;
		j += 8;
		if (j + 8 >= filter->vallen)
			break;
	}
	return 0;
}

static inline __attribute__((always_inline)) long
filter_32ty(struct selector_arg_filter *filter, char *args)
{
	__u32 *v = (__u32 *)&filter->value;
	int i, j = 0;

#pragma unroll
	for (i = 0; i < MAX_MATCH_VALUES; i++) {
		__u32 w = v[i];
		bool res = (*(u32 *)args == w);

		if (filter->op == op_filter_eq && res)
			return 1;
		if (filter->op == op_filter_neq && !res)
			return 1;
		// placed here to allow llvm unroll this loop
		j += 4;
		if (j + 8 >= filter->vallen)
			break;
	}
	return 0;
}

static inline __attribute__((always_inline)) size_t type_to_min_size(int type,
								     int argm)
{
	switch (type) {
	case fd_ty:
	case file_ty:
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

	// nop or something else we do not process here
	default:
		return 0;
	}
}

#define INDEX_MASK 0x3ff

static inline __attribute__((always_inline)) int
selector_arg_offset(__u8 *f, struct msg_generic_kprobe *e, __u32 selector)
{
	struct selector_arg_filter *filter;
	struct selector_binary_filter *binary;
	long seloff, argoff, pass;
	__u32 len, index;
	char *args;

	/* Find selector offset byte index */
	selector *= 4;
	selector += 4;

	/* read the start offset of the corresponding selector */
	selector = *(__u32 *)((__u64)f + (selector & INDEX_MASK));

	selector &= INDEX_MASK;
	selector += 8; /* 8: selector value and selector header */

	/* matchPid */
	len = *(__u32 *)((__u64)f +
			 (selector &
			  INDEX_MASK)); /* (sizeof(pid1) + sizeof(pid2) + ... + 4) */
	selector += len;

	/* matchNamespace */
	len = *(__u32 *)((__u64)f +
			 (selector &
			  INDEX_MASK)); /* (sizeof(ns1) + sizeof(ns2) + ... + 4) */
	selector += len;

	/* matchCapabilities */
	len = *(__u32 *)((__u64)f +
			 (selector &
			  INDEX_MASK)); /* (sizeof(cap1) + sizeof(cap2) + ... + 4) */
	selector += len;

	/* matchNamespaceChanges */
	len = *(__u32 *)((__u64)f +
			 (selector &
			  INDEX_MASK)); /* (sizeof(nc1) + sizeof(nc2) + ... + 4) */
	selector += len;

	/* matchCapabilityChanges */
	len = *(__u32 *)((__u64)f +
			 (selector &
			  INDEX_MASK)); /* (sizeof(cap1) + sizeof(cap1) + ... + 4) */
	selector += len;

	/* seloff must leave space for verifier to walk strings
	 * so we set inside 4k maximum. Advance to binary matches.
	 */
	seloff = (selector & INDEX_MASK);
	binary = (struct selector_binary_filter *)&f[seloff];

	/* Run binary name filters
	 */
	if (binary->op == op_filter_in) {
		struct execve_map_value *execve;
		bool walker = 0;
		__u32 ppid;

		execve = event_find_curr(&ppid, 0, &walker);
		if (!execve)
			return 0;
		if (binary->index[0] != execve->binary &&
		    binary->index[1] != execve->binary &&
		    binary->index[2] != execve->binary &&
		    binary->index[3] != execve->binary)
			return 0;
	}

	/* Advance to matchArgs we use fixed size binary filters for now. It helps
	 * the verifier and its still unclear how many entries are needed. At any
	 * rate each entry is a uint32 now and we should really be able to pack
	 * an entry into a byte which would give us 4x more entries.
	 */
	seloff += sizeof(struct selector_binary_filter);
	if (seloff > 3800) {
		return 0;
	}

	/* Making binary selectors fixes size helps on some kernels */
	asm volatile("%[seloff] &= 0xeff;\n" ::[seloff] "+r"(seloff) :);
	filter = (struct selector_arg_filter *)&f[seloff];

	if (filter->arglen <= 4) // no filters
		return seloff;

	index = filter->index;
	if (index > 5)
		return 0;

	asm volatile("%[index] &= 0x7;\n" ::[index] "+r"(index) :);
	argoff = e->argsoff[index];
	asm volatile("%[argoff] &= 0xeff;\n" ::[argoff] "+r"(argoff) :);
	args = &e->args[argoff];

	switch (filter->type) {
	case fd_ty:
		/* Advance args past fd */
		args += 4;
	case file_ty:
		pass = filter_file_buf(filter, args);
		break;
	case string_type:
	case char_buf:
		pass = filter_char_buf(filter, args);
		break;
	case s64_ty:
	case u64_ty:
		pass = filter_64ty(filter, args);
		break;
	case size_type:
	case int_type:
	case s32_ty:
	case u32_ty:
		pass = filter_32ty(filter, args);
		break;
	default:
		pass = 1; // no policy in place
		break;
	}

	return pass ? seloff : 0;
}

static inline __attribute__((always_inline)) int filter_args_reject(void)
{
	u64 tid = get_current_pid_tgid();
	retprobe_map_clear(tid);
	return 0;
}

static inline __attribute__((always_inline)) int
filter_args(struct msg_generic_kprobe *e, int index, void *filter_map)
{
	int zero = 0;
	__u8 *f;

	/* No filters and no selectors so just accepts */
	f = map_lookup_elem(filter_map, &zero);
	if (!f) {
		return 1;
	}

	/* No selectors, accept by default */
	if (!e->active[SELECTORS_ACTIVE]) {
		return 1;
	}

	/* We ran process filters early as a prefilter to drop unrelated
	 * events early. Now we need to ensure that active pid sselectors
	 * have their arg filters run.
	 */
	if (index > SELECTORS_ACTIVE)
		return filter_args_reject();

	if (e->active[index]) {
		int pass = selector_arg_offset(f, e, index);
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

struct bpf_map_def __attribute__((section("maps"), used)) fdinstall_map = {
	.type = BPF_MAP_TYPE_LRU_HASH,
	.key_size = sizeof(struct fdinstall_key),
	.value_size = sizeof(struct fdinstall_value),
	.max_entries = 32000,
};

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
	asm volatile("%[fd] &= 0xf;\n" : [fd] "+r"(fd) :);
	if (fd > 5) {
		return 0;
	}
	fdoff = e->argsoff[fd];
	asm volatile("%[fdoff] &= 0xeff;\n" : [fdoff] "+r"(fdoff) :);
	key.pad = 0;
	key.fd = *(__u32 *)&e->args[fdoff];
	key.tid = get_current_pid_tgid() >> 32;

	if (follow) {
		__u32 size;

		asm volatile("%[name] &= 0xf;\n" : [name] "+r"(name) :);
		if (name > 5)
			return 0;
		nameoff = e->argsoff[name];
		asm volatile("%[nameoff] &= 0xeff;\n"
			     : [nameoff] "+r"(nameoff)
			     :);

		size = *(__u32 *)&e->args[nameoff];
		asm volatile("%[size] &= 0xff;\n" : [size] "+r"(size) :);

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

	asm volatile("%[oldfd] &= 0xf;\n" : [oldfd] "+r"(oldfd) :);
	if (oldfd > 5)
		return 0;
	oldfdoff = e->argsoff[oldfd];
	asm volatile("%[oldfdoff] &= 0xeff;\n" : [oldfdoff] "+r"(oldfdoff) :);
	key.pad = 0;
	key.fd = *(__u32 *)&e->args[oldfdoff];
	key.tid = get_current_pid_tgid() >> 32;

	val = map_lookup_elem(&fdinstall_map, &key);
	if (val) {
		asm volatile("%[newfd] &= 0xf;\n" : [newfd] "+r"(newfd) :);
		if (newfd > 5)
			return 0;
		newfdoff = e->argsoff[newfd];
		asm volatile("%[newfdoff] &= 0xeff;\n"
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
__do_action_sigkill(struct bpf_map_def *config_map)
{
	struct event_config *config;
	int zero = 0;

	config = map_lookup_elem(config_map, &zero);
	if (config && config->sigkill)
		send_signal(FGS_SIGKILL);
}
#else
static inline __attribute__((always_inline)) void
__do_action_sigkill(struct bpf_map_def *config_map)
{
}
#endif /* __LARGE_BPF_PROG */

static inline __attribute__((always_inline)) long
__do_action(long i, struct msg_generic_kprobe *e,
	    struct selector_action *actions, struct bpf_map_def *override_tasks,
	    struct bpf_map_def *config_map)
{
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
	case ACTION_SIGKILL:
		__do_action_sigkill(config_map);
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
	default:
		break;
	}
	if (!err) {
		e->action = action;
		return ++i;
	}
	return -1;
}

static inline __attribute__((always_inline)) long
do_actions(struct msg_generic_kprobe *e, struct selector_action *actions,
	   struct bpf_map_def *override_tasks, struct bpf_map_def *config_map)
{
	/* Clang really doesn't want to unwind a loop here. */
	long i = 0;
	i = __do_action(i, e, actions, override_tasks, config_map);
	if (i)
		goto out;
	i = __do_action(i, e, actions, override_tasks, config_map);
out:
	return i > 0 ? true : 0;
}

#define MAX_SELECTORS 8

static inline __attribute__((always_inline)) long
filter_read_arg(void *ctx, int index, struct bpf_map_def *heap,
		struct bpf_map_def *filter, struct bpf_map_def *tailcalls,
		struct bpf_map_def *override_tasks,
		struct bpf_map_def *config_map)
{
	struct msg_generic_kprobe *e;
	int pass, zero = 0;
	size_t total;

	e = map_lookup_elem(heap, &zero);
	if (!e)
		return 0;
	pass = filter_args(e, index, filter);
	if (!pass) {
		index++;
		if (index > MAX_SELECTORS || !e->active[index])
			return filter_args_reject();
		tail_call(ctx, tailcalls, index + 5);
		return 2;
	}

	// If pass >1 then we need to consult the selector actions
	// otherwise pass==1 indicates using default action.
	if (pass > 1) {
		struct selector_arg_filter *arg;
		struct selector_action *actions;
		int actoff;
		__u8 *f;

		f = map_lookup_elem(filter, &zero);
		if (f) {
			bool postit;

			asm volatile("%[pass] &= 0xeff;\n"
				     : [pass] "+r"(pass)
				     :);
			arg = (struct selector_arg_filter *)&f[pass];

			actoff = pass + arg->arglen;
			asm volatile("%[actoff] &= 0xeff;\n"
				     : [actoff] "+r"(actoff)
				     :);
			actions = (struct selector_action *)&f[actoff];

			postit = do_actions(e, actions, override_tasks,
					    config_map);
			if (!postit)
				return 1;
		}
	}

#ifdef __NS_CHANGES_FILTER
	/* update the namespaces if we matched a change on that */
	if (e->match_ns) {
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
	if (e->match_cap) {
		__u32 pid = (get_current_pid_tgid() >> 32);
		struct task_struct *task =
			(struct task_struct *)get_current_task();
		struct execve_map_value *enter = execve_map_get_noinit(
			pid); // we don't want to init that if it does not exist
		if (enter)
			get_caps(&(enter->caps), task);
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
	      long orig_off, unsigned long arg, int argm, void *filter_map)
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
	case path_ty:
		size = copy_path(args, path_arg);
		break;
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
		size = copy_char_buf(ctx, orig_off, arg, argm, e);
		break;
	case char_iovec:
		size = copy_char_iovec(ctx, orig_off, arg, argm, e);
		break;
	case const_buf_type: {
		int err;

		// bound size to 1023 to help the verifier out
		size = argm & 0x03ff;
		err = probe_read(args, size, (char *)arg);
		break;
	}
	default:
		size = 0;
		break;
	}
	return size;
}
