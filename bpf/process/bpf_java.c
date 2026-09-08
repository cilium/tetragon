// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Tetragon */

#include "vmlinux.h"
#include "api.h"
#include "bpf_helpers.h"
#include "common.h"
#include "java.h"
#include "msg_types.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

#define CLOCK_MONOTONIC 1
#define JAVA_TIMER_NS 1000000ULL

struct {
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, 65536);
} tg_java_urb SEC(".maps");

struct java_timer {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct java_timer);
} tg_java_timers SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 65536);
} tg_rb_events SEC(".maps");

static long drain_java_record(struct bpf_dynptr *record, void *ctx __maybe_unused)
{
	struct execve_map_value *curr;
	struct msg_java *out;
	__u32 pid;
	__u8 extra;

	/* A successful byte read at the first invalid offset means the producer
	 * submitted a record larger than the fixed wire contract. A short record
	 * is rejected by the full dynptr_read below. */
	if (!dynptr_read(&extra, sizeof(extra), record, sizeof(struct msg_java), 0))
		return 0;

	out = ringbuf_reserve(&tg_rb_events, sizeof(*out), 0);
	if (!out)
		return 0;

	if (dynptr_read(out, sizeof(*out), record, 0, 0)) {
		ringbuf_discard(out, 0);
		return 0;
	}

	/* Treat routing and process metadata as part of the bridge contract, not
	 * as producer controlled input. The source timestamp and Java identity
	 * stay intact. */
	pid = out->current.pid;
	curr = execve_map_get_noinit(pid);
	out->common.op = MSG_OP_JAVA;
	out->common.flags = 0;
	out->common.pad[0] = 0;
	out->common.pad[1] = 0;
	out->common.size = sizeof(*out);
	if (curr && curr->key.ktime <= out->common.ktime) {
		out->current = curr->key;
	} else {
		out->common.flags |= MSG_COMMON_FLAG_PROCESS_NOT_FOUND;
		out->current.pid = pid;
		out->current.ktime = out->common.ktime;
	}
	out->current.pad[0] = 0;
	out->current.pad[1] = 0;
	out->current.pad[2] = 0;
	out->current.pad[3] = 0;
	out->pad[0] = 0;
	out->pad[1] = 0;
	out->pad[2] = 0;
	out->pad[3] = 0;
	ringbuf_submit(out, 0);
	return 0;
}

static int java_timer_cb(void *map __maybe_unused, __u32 *key __maybe_unused,
			 struct java_timer *value)
{
	user_ringbuf_drain(&tg_java_urb, drain_java_record, (void *)0, 0);
	timer_start(&value->timer, JAVA_TIMER_NS, 0);
	return 0;
}

SEC("syscall")
int java_timer_init(void *ctx __maybe_unused)
{
	struct java_timer *value;
	__u32 key = 0;
	int err;

	value = map_lookup_elem(&tg_java_timers, &key);
	if (!value)
		return 1;

	err = timer_init(&value->timer, &tg_java_timers, CLOCK_MONOTONIC);
	if (err)
		return err;
	err = timer_set_callback(&value->timer, java_timer_cb);
	if (err)
		return err;
	return timer_start(&value->timer, JAVA_TIMER_NS, 0);
}
