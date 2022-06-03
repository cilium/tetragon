#include "data_msg.h"

static inline __attribute__((always_inline)) long
__do_bytes(void *ctx, struct msg_data *msg, unsigned long uptr, size_t bytes)
{
	size_t max = sizeof(msg->arg) - 1;
	size_t rd_bytes, size;
	int err;

	rd_bytes = bytes > max ? max : bytes;
	msg->common.size = offsetof(struct msg_data, arg) + rd_bytes;

	/* Code movement from clang forces us to inline bounds checks here */
	asm volatile("%[rd_bytes] &= 0x7fff;\n"
		     "if %[rd_bytes] < 32736 goto +1\n;"
		     "%[rd_bytes] = 32736;\n"
		     :
		     : [rd_bytes] "+r"(rd_bytes)
		     :);
	err = probe_read(&msg->arg[0], rd_bytes, (char *)uptr);
	if (err < 0)
		return err;

	size = rd_bytes + offsetof(struct msg_data, arg);

	/* Code movement from clang forces us to inline bounds checks here */
	asm volatile("%[size] &= 0x7fff;\n" : : [size] "+r"(size) :);
	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, msg, size);
	return rd_bytes;
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

static int data_event(void *ctx, void *out, unsigned long uptr, size_t size,
		      bool cont, struct bpf_map_def *heap,
		      long (*do_data_event)(void *, struct msg_data *,
					    unsigned long, size_t))
{
	struct data_event_desc *desc = out;
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
	desc->flags = cont ? DATA_EVENT_DESC_FLAGS_CONT : 0;

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
data_event_bytes(void *ctx, void *out, unsigned long uptr, size_t size,
		 bool cont, struct bpf_map_def *heap)
{
	return data_event(ctx, out, uptr, size, cont, heap, do_bytes);
}
