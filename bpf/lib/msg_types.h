// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef _MSG_TYPES_
#define _MSG_TYPES_

/* Msg Types */
enum msg_ops {
	MSG_OP_UNDEF = 0,
	MSG_OP_EXECVE = 5,
	MSG_OP_EXIT = 7,
	MSG_OP_GENERIC_KPROBE = 13,
	MSG_OP_GENERIC_TRACEPOINT = 14,
	MSG_OP_GENERIC_UPROBE = 15,
	MSG_OP_GENERIC_LSM = 16,
	MSG_OP_GENERIC_USDT = 17,

	MSG_OP_TEST = 254,

	/* These ops went through a few iterations of experimentation
	 * and some of those experiments exist in the wild. So just
	 * bump deprecated space to some large value and start over.
	 * This way its easy to phase out the old ones. And any new
	 * ops are clear to see in database and logs.
	 */
	MSG_OP_DEPRECATE_SPACE = 1000,

	MSG_OP_CLONE = 23,

	MSG_OP_DATA = 24,

	MSG_OP_CGROUP = 25,

	MSG_OP_LOADER = 26,

	MSG_OP_THROTTLE = 27,

	MSG_OP_MAX,
};

enum msg_cgroup_ops {
	MSG_OP_CGROUP_UNDEF = 0,
	MSG_OP_CGROUP_MKDIR =
		1, /* cgroup_mkdir tracepoint, used for debugging */
	MSG_OP_CGROUP_RMDIR =
		2, /* cgroup_rmdir tracepoint, used for debugging */
	MSG_OP_CGROUP_RELEASE =
		3, /* cgroup_release tracepoint, used for debugging */
	MSG_OP_CGROUP_ATTACH_TASK = 10, /* cgroup_attach_task tracepoint */
};

#endif // _MSG_TYPES_
