/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#ifndef __DATA_EVENT_H__
#define __DATA_EVENT_H__

#include "bpf_tracing.h"
#include "data_msg.h"
#include "types/probe_read_kernel_or_user.h"

static inline __attribute__((always_inline)) long
__do_bytes(void *ctx, struct msg_data *msg, unsigned long uptr, size_t bytes, bool userspace)
{
	int err;

	/* Code movement from clang forces us to inline bounds checks here */
	asm volatile goto(
		"if %[bytes] < 0 goto %l[b]\n;"
		"if %[bytes] < " XSTR(MSG_DATA_ARG_LEN) " goto %l[a]\n;"
		:
		: [bytes] "+r"(bytes)::a, b);
	bytes = MSG_DATA_ARG_LEN;
a:
	// < 5.3 verifier still requires value masking like 'val &= xxx'
#ifndef __LARGE_BPF_PROG
	err = probe_read_kernel_or_user_masked(&msg->arg[0], bytes, 0x3fff, (char *)uptr, userspace);
#else
	err = probe_read_kernel_or_user_masked(&msg->arg[0], bytes, 0x7fff, (char *)uptr, userspace);
#endif
	if (err < 0)
		return err;

	msg->common.size = offsetof(struct msg_data, arg) + bytes;
#ifndef __LARGE_BPF_PROG
	perf_event_output_metric(ctx, MSG_OP_DATA, &tcpmon_map, BPF_F_CURRENT_CPU, msg, msg->common.size & 0x7fff);
#else
	perf_event_output_metric(ctx, MSG_OP_DATA, &tcpmon_map, BPF_F_CURRENT_CPU, msg, msg->common.size & 0xffff);
#endif
	return bytes;
b:
	return -1;
}

static inline __attribute__((always_inline)) long
do_bytes(void *ctx, struct msg_data *msg, unsigned long arg, size_t bytes, bool userspace)
{
	size_t rd_bytes = 0;
	int err, i __maybe_unused;

#ifdef __LARGE_BPF_PROG
	for (i = 0; i < 10; i++) {
		err = __do_bytes(ctx, msg, arg + rd_bytes, bytes - rd_bytes, userspace);
		if (err < 0)
			return err;
		rd_bytes += err;
		if (rd_bytes == bytes)
			return rd_bytes;
	}
#else
#define BYTES_COPY                                                               \
	err = __do_bytes(ctx, msg, arg + rd_bytes, bytes - rd_bytes, userspace); \
	if (err < 0)                                                             \
		return err;                                                      \
	rd_bytes += err;                                                         \
	if (rd_bytes == bytes)                                                   \
		return rd_bytes;

#define BYTES_COPY_5 BYTES_COPY BYTES_COPY BYTES_COPY BYTES_COPY BYTES_COPY

	BYTES_COPY_5
	BYTES_COPY_5

#undef BYTES_COPY_5
#endif /* __LARGE_BPF_PROG */

	/* leftover */
	return rd_bytes;
}

static inline __attribute__((always_inline)) long
__do_str(void *ctx, struct msg_data *msg, unsigned long arg, bool *done, bool userspace)
{
	size_t size, max = sizeof(msg->arg) - 1;
	long ret;

	/* Code movement from clang forces us to inline bounds checks here */
	asm volatile("%[max] &= 0x7fff;\n"
		     "if %[max] < 32736 goto +1\n;"
		     "%[max] = 32736;\n"
		     :
		     : [max] "+r"(max)
		     :);

	ret = probe_read_kernel_or_user_str(&msg->arg[0], max, (char *)arg, userspace);

	if (ret < 0)
		return ret;

	*done = ret != max;
	if (ret == 0)
		return 0;
	/* cut out the zero byte */
	ret -= 1;

	size = ret + offsetof(struct msg_data, arg);
	/* Code movement from clang forces us to inline bounds checks here */
	asm volatile("%[size] &= 0x7fff;\n"
		     :
		     : [size] "+r"(size)
		     :);
	msg->common.size = size;
	perf_event_output_metric(ctx, MSG_OP_DATA, &tcpmon_map, BPF_F_CURRENT_CPU, msg, size);
	return ret;
}

static inline __attribute__((always_inline)) long
do_str(void *ctx, struct msg_data *msg, unsigned long arg,
       size_t bytes __maybe_unused, bool userspace)
{
	size_t rd_bytes = 0;
	bool done = false;
	long ret;
	int i;

#define __CNT 2
#pragma unroll
	for (i = 0; i < __CNT; i++) {
		ret = __do_str(ctx, msg, arg + rd_bytes, &done, userspace);
		if (ret < 0)
			return ret;
		rd_bytes += ret;
		if (done)
			break;
	}
#undef __CNT

	/* we have no idea what's string leftover */
	return rd_bytes;
}

static inline __attribute__((always_inline)) size_t data_event(
	void *ctx, struct data_event_desc *desc, unsigned long uptr,
	size_t size, struct bpf_map_def *heap,
	long (*do_data_event)(void *, struct msg_data *, unsigned long, size_t, bool),
	bool userspace)
{
	struct msg_data *msg;
	int zero = 0, err;

	msg = map_lookup_elem(heap, &zero);
	if (!msg)
		return 0;

	msg->common.op = MSG_OP_DATA;
	msg->common.flags = 0;
	msg->common.pad[0] = 0;
	msg->common.pad[1] = 0;

	msg->id.pid = get_current_pid_tgid();
	if (msg->id.pid == (__u64)-22) // -EINVAL -- current == NULL
		msg->id.pid = PT_REGS_FP_CORE((struct pt_regs *)ctx);

	msg->id.time = ktime_get_ns();
	desc->id = msg->id;

	/*
	 * Notes:
	 * The @size argument is valid only for do_bytes, it's -1 * for do_str.
	 * The do_data_event callback returns size of posted data.
	 * Leftover for data_event_str is always 0, because we don't know
	 * how much more was there to copy.
	 */
	err = do_data_event(ctx, msg, uptr, size, userspace);

	if (err < 0) {
		desc->error = err;
		desc->pad = 0;
		desc->leftover = 0;
		desc->size = 0;
	} else {
		desc->error = 0;
		desc->pad = 0;
		desc->leftover = size == -1 ? 0 : size - err;
		desc->size = err;
	}
	return sizeof(*desc);
}

/**
 * data_event_bytes - sends data event for raw data
 *
 * @uptr: pointer to data
 * @size: size of the data
 *
 * Sends data event with raw data specified by @uptr and @size and
 * writes status values into @desc object.
 *
 * Returns size of struct @desc object or 0 in case of error.
 */
static inline __attribute__((always_inline)) size_t
data_event_bytes(void *ctx, struct data_event_desc *desc, unsigned long uptr,
		 size_t size, struct bpf_map_def *heap, bool userspace)
{
	return data_event(ctx, desc, uptr, size, heap, do_bytes, userspace);
}

/**
 * data_event_str - sends data event for string
 *
 * @uptr: pointer to string
 *
 * Sends data event with string specified by @uptr and writes status
 * values into @desc object.
 *
 * Returns size of struct @desc object or 0 in case of error.
 */
static inline __attribute__((always_inline)) size_t
data_event_str(void *ctx, struct data_event_desc *desc, unsigned long uptr,
	       struct bpf_map_def *heap, bool userspace)
{
	return data_event(ctx, desc, uptr, -1, heap, do_str, userspace);
}

#endif /* __DATA_EVENT_H__ */
