// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef _PROCESS__
#define _PROCESS__

#include "bpf_event.h"
#include "bpf_helpers.h"
#include "bpf_cred.h"
#include "../process/string_maps.h"
#include "api.h"
#include "policy_stats.h"
#include "errmetrics.h"
#include "environ_conf.h"

/* Applying 'packed' attribute to structs causes clang to write to the
 * members byte-by-byte, as offsets may not be aligned. This is bad for
 * performance, instruction count and complexity, so don't apply this
 * attribute to structs where members are correctly aligned already
 * (e.g. by padding, layout).
 */

/* These are your sizing variables. Because we are running in BPF and must
 * be bounded in terms of loop iterations and memory usage we have to set
 * worse case bounds.
 *
 * For tuning the following values can be easily changed with memory and
 * instruction count tradeoffs,
 *
 *  MAXARGS - more or less arguments on command line
 *  MAXARGLENGTH - max length of any individual arg
 *  BUFFER - this is the total number of bytes per pid consumed for args
 *
 * If buffer is full before maxargs and/or maxarglength is consumed then
 * processing stops.
 */

/* Max length of any given arg */
#define MAXARGLENGTH 256
/* This is the absolute buffer size for args and filenames including some
 * extra head room so we can append last args string to buffer. The extra
 * headroom is an unfortunate result of bounds on offset/size in
 * event_args_builder().
 *
 * For example given an offset bounds
 *
 *   offset <- (0, 100)
 *
 * We will read into the buffer using this offset giving a max offset
 * of eargs + 100.
 *
 *   args[offset] <- (0, 100)
 *
 * Now we want to read this with call 45 aka probe_read_str as follows,
 * where 'kernel_struct_arg' is the kernel data struct we are reading.
 *
 *   probe_read_str(args[offset], size, kernel_struct_arg)
 *
 * But we have a bit of a problem determining if 'size' is out of array
 * range. The math would be,
 *
 *   size = length - offset
 *
 * Giving the remainder of the buffer,
 *
 * args          offset             length
 *    |---------------|------------------|
 *
 *                    |-------size-------|
 *
 * But verifier math works on bounds so bounds analysis of size is the
 * following,
 *
 *   length = 1024
 *   offset = (0, 100)
 *
 *   size = length - offset
 *   size = (1024) - (0, 100)
 *   size <- (924, 1124)
 *
 * And verifier throws an error because args[offset + size] with bounds
 * anaylsis,
 *
 *   args_(max)[100 + 1024] = args_(max)[1124]
 *
 * To circumvent this, at least until we teach the verifier about
 * dependent variables, create a maxarg value and pad arg buffer with
 * it. Giving a args buffer of size 'length + pad' with above bounds
 * analysis,
 *
 *   size = length - offset
 *   size = (1024) - (0, 100)
 *   if size > pad goto done
 *   size <- (924, 1124) // 1124 < length + pad
 *
 * Phew all clear now?
 */
#define CWD_MAX		   4096
#define BUFFER		   1024
#define SIZEOF_MSG_PROCESS sizeof(struct msg_process)
#define PADDED_BUFFER \
	(BUFFER + MAXARGLENGTH + SIZEOF_MSG_PROCESS + SIZEOF_MSG_PROCESS + CWD_MAX)
#define PATHNAME_SIZE 256

/* Msg flags */
#define EVENT_UNKNOWN		      0x00
#define EVENT_EXECVE		      0x01
#define EVENT_ENVS_DATA		      0x02
#define EVENT_PROCFS		      0x04
#define EVENT_ENVS_ERROR	      0x08
#define EVENT_TRUNC_ARGS	      0x10
#define EVENT_AVAIL_3		      0x20
#define EVENT_MISS		      0x40
#define EVENT_AVAIL_4		      0x80
#define EVENT_ERROR_FILENAME	      0x100
#define EVENT_ERROR_ARGS	      0x200
#define EVENT_NEEDS_CWD		      0x400
#define EVENT_NO_CWD_SUPPORT	      0x800
#define EVENT_ROOT_CWD		      0x1000
#define EVENT_ERROR_CWD		      0x2000
#define EVENT_CLONE		      0x4000
#define EVENT_AVAIL_5		      0x8000
#define EVENT_ERROR_CGROUP_NAME	      0x010000
#define EVENT_AVAIL_6		      0x020000
#define EVENT_ERROR_CGROUP_SUBSYSCGRP 0x040000
#define EVENT_ERROR_CGROUP_SUBSYS     0x080000
#define EVENT_ERROR_CGROUPS	      0x100000
#define EVENT_ERROR_CGROUP_ID	      0x200000
#define EVENT_ERROR_PATH_COMPONENTS   0x400000
#define EVENT_DATA_FILENAME	      0x800000
#define EVENT_DATA_ARGS		      0x1000000
#define EVENT_IN_INIT_TREE	      0x2000000

#define EVENT_COMMON_FLAG_CLONE 0x01

/* Docker IDs are unique at first 12 characters, but we want to get
 * 12chars plus any extra prefix used by the container environment.
 * Minikube for example prepends 'docker-' to the id. So lets copy
 * 32B and assume at least 12B of it is ID info.
 */
#define DOCKER_ID_LENGTH 128

struct msg_execve_key {
	__u32 pid; // Process TGID
	__u8 pad[4];
	__u64 ktime;
}; // All fields aligned so no 'packed' attribute.

/* This is the struct stored in bpf map to share info between
 * different execve hooks.
 */
struct execve_info {
	/* The secureexec is to reflect the kernel bprm->secureexec that is exposed
	 * to userspace through auxiliary vector which can be read from
	 * /proc/self/auxv or https://man7.org/linux/man-pages/man3/getauxval.3.html
	 *
	 * The AT_SECURE of auxv can have a value of 1 or 0 and it is set from
	 * the bprm->secureexec that is a bit field.
	 * If bprm->secureexec is 1 then it means executable should be treated securely.
	 * Most commonly, 1 indicates that the process is executing a set-user-ID
	 * or set-group-ID binary (so that its real and effective UIDs or GIDs differ
	 * from one another), or that it gained capabilities by executing a binary file
	 * that has capabilities (see capabilities(7)).
	 * Alternatively, a nonzero value may be triggered by a Linux Security Module.
	 * When this value is nonzero, the dynamic linker disables the use of certain
	 * environment variables.
	 *
	 * The secureexec here can have the following bit flags:
	 *   EXEC_SETUID or EXEC_SETGID
	 */
	__u32 secureexec;
	__u32 i_nlink; /* inode links */
	__u64 i_ino; /* inode number */
};

/* process information
 */
struct msg_process {
	__u32 size;
	__u32 pid; // Process TGID
	__u32 tid; // Process thread
	__u32 nspid;
	__u32 secureexec;
	__u32 uid;
	__u32 auid;
	__u32 flags;
	__u32 i_nlink;
	__u32 pad;
	__u64 i_ino;
	__u64 ktime;
	__u16 size_path;
	__u16 size_args;
	__u16 size_cwd;
	__u16 size_envs;
	char args[0];
}; // All fields aligned so no 'packed' attribute.

/* msg_clone_event holds only the necessary fields to construct a new entry from
 * the parent after a clone() event.
 */
struct msg_clone_event {
	struct msg_common common;
	struct msg_execve_key parent;
	__u32 tgid;
	__u32 tid;
	__u32 nspid;
	__u32 flags;
	__u64 ktime;
} __attribute__((packed));

struct exit_info {
	__u32 code;
	__u32 tid; // Thread ID
};

struct msg_exit {
	struct msg_common common;
	struct msg_execve_key current;
	struct exit_info info;
}; // All fields aligned so no 'packed' attribute.

enum {
	ns_uts = 0,
	ns_ipc = 1,
	ns_mnt = 2,
	ns_pid = 3,
	ns_pid_for_children = 4,
	ns_net = 5,
	ns_time = 6,
	ns_time_for_children = 7,
	ns_cgroup = 8,
	ns_user = 9,

	// If you update the value of ns_max_types you
	// should also update parseMatchNamespaces()
	// in kernel.go
	ns_max_types = 10,
};

struct msg_ns {
	union {
		struct {
			__u32 uts_inum;
			__u32 ipc_inum;
			__u32 mnt_inum;
			__u32 pid_inum;
			__u32 pid_for_children_inum;
			__u32 net_inum;
			__u32 time_inum;
			__u32 time_for_children_inum;
			__u32 cgroup_inum;
			__u32 user_inum;
		};
		__u32 inum[ns_max_types];
	};
}; // All fields aligned so no 'packed' attribute.

struct msg_k8s {
	__u64 cgrpid;
	__u64 cgrp_tracker_id;
	char docker_id[DOCKER_ID_LENGTH];
}; // All fields aligned so no 'packed' attribute.

#define MBSET_INVALID_ID 0xffffffff

#define SENT_FAILED_UNKNOWN 0 // unknown error
#define SENT_FAILED_ENOENT  1 // ENOENT
#define SENT_FAILED_E2BIG   2 // E2BIG
#define SENT_FAILED_EBUSY   3 // EBUSY
#define SENT_FAILED_EINVAL  4 // EINVAL
#define SENT_FAILED_ENOSPC  5 // ENOSPC
#define SENT_FAILED_EAGAIN  6 // EAGAIN
#define SENT_FAILED_MAX	    7

struct kernel_stats {
	__u64 sent_failed[256][SENT_FAILED_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct kernel_stats);
	__uint(max_entries, 1);
} tg_stats_map SEC(".maps");

FUNC_INLINE void
event_output_update_error_metric(u8 msg_op, long err)
{
	struct kernel_stats *valp;
	__u32 zero = 0;

	valp = map_lookup_elem(&tg_stats_map, &zero);
	if (valp) {
		switch (err) {
		case -2: // ENOENT
			lock_add(&valp->sent_failed[msg_op][SENT_FAILED_ENOENT], 1);
			break;
		case -7: // E2BIG
			lock_add(&valp->sent_failed[msg_op][SENT_FAILED_E2BIG], 1);
			break;
		case -11: // EAGAIN
			lock_add(&valp->sent_failed[msg_op][SENT_FAILED_EAGAIN], 1);
			break;
		case -16: // EBUSY
			lock_add(&valp->sent_failed[msg_op][SENT_FAILED_EBUSY], 1);
			break;
		case -22: // EINVAL
			lock_add(&valp->sent_failed[msg_op][SENT_FAILED_EINVAL], 1);
			break;
		case -28: // ENOSPC
			lock_add(&valp->sent_failed[msg_op][SENT_FAILED_ENOSPC], 1);
			break;
		default:
			lock_add(&valp->sent_failed[msg_op][SENT_FAILED_UNKNOWN], 1);
			break;
		}
	}
}

FUNC_INLINE void
perf_event_output_metric(void *ctx, u8 msg_op, void *map, u64 flags, void *data, u64 size)
{
	long err;

	err = perf_event_output(ctx, map, flags, data, size);
	if (err < 0) {
		event_output_update_error_metric(msg_op, err);
		return;
	}

	policy_stats_update(POLICY_POST);
}

#ifdef __V511_BPF_PROG
FUNC_INLINE long
event_output(void *ctx, void *data, u64 size)
{
	struct tetragon_conf *conf;
	int zero = 0;

	conf = map_lookup_elem(&tg_conf_map, &zero);
	if (conf && conf->use_perf_ring_buf)
		return perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, data, size);
	return ringbuf_output(&tg_rb_events, data, size, 0);
}

FUNC_INLINE void
event_output_metric(void *ctx, u8 msg_op, void *data, u64 size)
{
	struct tetragon_conf *conf;
	int zero = 0;
	long err;

	conf = map_lookup_elem(&tg_conf_map, &zero);
	if (conf && conf->use_perf_ring_buf) {
		perf_event_output_metric(ctx, msg_op, &tcpmon_map, BPF_F_CURRENT_CPU, data, size);
		return;
	}

	err = ringbuf_output(&tg_rb_events, data, size, 0);

	if (err < 0) {
		event_output_update_error_metric(msg_op, err);
		return;
	}

	policy_stats_update(POLICY_POST);
}
#else
FUNC_INLINE long
event_output(void *ctx, void *data, u64 size)
{
	return perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, data, size);
}

FUNC_INLINE void
event_output_metric(void *ctx, u8 msg_op, void *data, u64 size)
{
	perf_event_output_metric(ctx, msg_op, &tcpmon_map, BPF_F_CURRENT_CPU, data, size);
}
#endif
#endif //_PROCESS__
