/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright Authors of Cilium */

#ifndef __DATA_MSG_
#define __DATA_MSG_

struct data_event_id {
	__u64 pid;
	__u64 time;
} __attribute__((packed));

struct data_event_desc {
	__s32 error;
	__u32 leftover;
	struct data_event_id id;
} __attribute__((packed));

struct msg_data {
	struct msg_common common;
	struct data_event_id id;
	/* To have a fast way to check buffer size we use 32736
	 * as arg size, which is:
	 *   0x8000 - offsetof(struct msg_kprobe_arg, arg)
	 * so we can make verifier happy with:
	 *   'size &= 0x7fff' check
	 */
	char arg[32736];
} __attribute__((packed));

#endif /* __DATA_MSG_ */
