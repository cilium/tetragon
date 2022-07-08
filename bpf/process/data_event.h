/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright Authors of Cilium */

#include "data_msg.h"

static inline __attribute__((always_inline)) long
__do_bytes(void *ctx, struct msg_data *msg, unsigned long uptr, size_t bytes)
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
	err = probe_read(&msg->arg[0], bytes, (char *)uptr);
	if (err < 0)
		return err;

	msg->common.size = offsetof(struct msg_data, arg) + bytes;
	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, msg,
			  msg->common.size);
	return bytes;
b:
	return -1;
}

static long do_bytes(void *ctx, struct msg_data *msg, unsigned long arg,
		     size_t bytes)
{
	size_t rd_bytes = 0;
	int err, i;

#ifdef __LARGE_BPF_PROG
#define __CNT 10
#else
#define __CNT 8
#pragma unroll
#endif
	for (i = 0; i < __CNT; i++) {
		err = __do_bytes(ctx, msg, arg + rd_bytes, bytes - rd_bytes);
		if (err < 0)
			return err;
		rd_bytes += err;
		if (rd_bytes == bytes)
			return 0;
	}
#undef __CNT

	/* leftover */
	return bytes - rd_bytes;
}

static inline __attribute__((always_inline)) long
__do_str(void *ctx, struct msg_data *msg, unsigned long arg,
	 size_t bytes __maybe_unused)
{
	size_t size, max = sizeof(msg->arg) - 1;
	int err;

	/* Code movement from clang forces us to inline bounds checks here */
	asm volatile("%[max] &= 0x7fff;\n"
		     "if %[max] < 32736 goto +1\n;"
		     "%[max] = 32736;\n"
		     :
		     : [max] "+r"(max)
		     :);

	err = probe_read_str(&msg->arg[0], max, (char *)arg);
	if (err < 0)
		return err;

	/* cut out the zero byte */
	err -= 1;

	msg->common.size = offsetof(struct msg_data, arg) + err;

	size = err + offsetof(struct msg_data, arg);

	/* Code movement from clang forces us to inline bounds checks here */
	asm volatile("%[size] &= 0x7fff;\n" : : [size] "+r"(size) :);
	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, msg, size);
	return err == max ? 0 : 1;
}

static long do_str(void *ctx, struct msg_data *msg, unsigned long arg,
		   size_t bytes __maybe_unused)
{
	size_t rd_bytes = 0;
	int err, i;

#ifdef __LARGE_BPF_PROG
#define __CNT 10
#else
#define __CNT 2
#pragma unroll
#endif
	for (i = 0; i < __CNT; i++) {
		err = __do_str(ctx, msg, arg + rd_bytes, bytes - rd_bytes);
		if (err < 0)
			return err;
		if (err == 1)
			return 0;
	}
#undef __CNT

	/* we have no idea what's string leftover */
	return -1;
}

static inline __attribute__((always_inline)) int data_event(
	void *ctx, struct data_event_desc *desc, unsigned long uptr,
	size_t size, struct bpf_map_def *heap,
	long (*do_data_event)(void *, struct msg_data *, unsigned long, size_t))
{
	struct msg_data *msg;
	int zero = 0, err;

	msg = map_lookup_elem(heap, &zero);
	if (!msg)
		return -1;

	msg->common.op = MSG_OP_DATA;
	msg->common.flags = 0;
	msg->common.pad[0] = 0;
	msg->common.pad[1] = 0;

	msg->id.pid = get_current_pid_tgid();
	msg->id.time = ktime_get_ns();
	desc->id = msg->id;

	err = do_data_event(ctx, msg, uptr, size);
	if (err < 0) {
		desc->error = err;
		desc->leftover = 0;
	} else {
		desc->error = 0;
		desc->leftover = err;
	}
	return sizeof(*desc);
}

static inline __attribute__((always_inline)) size_t
data_event_bytes(void *ctx, struct data_event_desc *desc, unsigned long uptr,
		 size_t size, struct bpf_map_def *heap)
{
	return data_event(ctx, desc, uptr, size, heap, do_bytes);
}

static inline __attribute__((always_inline)) size_t
data_event_str(void *ctx, struct data_event_desc *desc, unsigned long uptr,
	       struct bpf_map_def *heap)
{
	return data_event(ctx, desc, uptr, -1, heap, do_str);
}
