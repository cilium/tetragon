// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef _PROCESS__
#define _PROCESS__

#include "bpf_event.h"
#include "bpf_helpers.h"
#include "bpf_cred.h"
#include "../process/string_maps.h"

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

/* Max number of args to parse */
#define MAXARGS 20
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
#define CWD_MAX	     256
#define BUFFER	     1024
#define SIZEOF_EVENT 56
#define PADDED_BUFFER \
	(BUFFER + MAXARGLENGTH + SIZEOF_EVENT + SIZEOF_EVENT + CWD_MAX)
/* This is the usable buffer size for args and filenames. It is calculated
 * as the (BUFFER SIZE - sizeof(parent) - sizeof(curr) but unfortunately
 * preprocess doesn't know types so we do it manually without sizeof().
 */
#define ARGSBUFFER	 (BUFFER - SIZEOF_EVENT - SIZEOF_EVENT)
#define __ASM_ARGSBUFFER 976
#define ARGSBUFFERMASK	 (ARGSBUFFER - 1)
#define MAXARGMASK	 (MAXARG - 1)
#define PATHNAME_SIZE	 256

/* Task flags */
#ifndef PF_KTHREAD
#define PF_KTHREAD 0x00200000 /* I am a kernel thread */
#endif

/* Msg flags */
#define EVENT_UNKNOWN		      0x00
#define EVENT_EXECVE		      0x01
#define EVENT_EXECVEAT		      0x02
#define EVENT_PROCFS		      0x04
#define EVENT_TRUNC_FILENAME	      0x08
#define EVENT_TRUNC_ARGS	      0x10
#define EVENT_TASK_WALK		      0x20
#define EVENT_MISS		      0x40
#define EVENT_NEEDS_AUID	      0x80
#define EVENT_ERROR_FILENAME	      0x100
#define EVENT_ERROR_ARGS	      0x200
#define EVENT_NEEDS_CWD		      0x400
#define EVENT_NO_CWD_SUPPORT	      0x800
#define EVENT_ROOT_CWD		      0x1000
#define EVENT_ERROR_CWD		      0x2000
#define EVENT_CLONE		      0x4000
#define EVENT_ERROR_SOCK	      0x8000
#define EVENT_ERROR_CGROUP_NAME	      0x010000
#define EVENT_ERROR_CGROUP_KN	      0x020000
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
 *
 * Manually linked to ARGSBUFFER and PADDED_BUFFER if this changes then please
 * also change SIZEOF_EVENT.
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
	char *args;
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

#define BINARY_PATH_MAX_LEN 256

struct heap_exe {
	char buf[BINARY_PATH_MAX_LEN];
	char end[STRING_POSTFIX_MAX_LENGTH];
	__u32 len;
	__u32 error;
	__u32 arg_len;
	__u32 arg_start;
}; // All fields aligned so no 'packed' attribute.

struct msg_execve_event {
	struct msg_common common;
	struct msg_k8s kube;
	struct msg_execve_key parent;
	__u64 parent_flags;
	struct msg_cred creds;
	struct msg_ns ns;
	struct msg_execve_key cleanup_key;
	/* if add anything above please also update the args of
	 * validate_msg_execve_size() in bpf_execve_event.c */
	union {
		struct msg_process process;
		char buffer[PADDED_BUFFER];
	};
	/* below fields are not part of the event, serve just as
	 * heap for execve programs
	 */
#ifdef __LARGE_BPF_PROG
	struct heap_exe exe;
#endif
}; // All fields aligned so no 'packed' attribute.

typedef __u64 mbset_t;

// This structure stores the binary path that was recorded on execve.
// Technically PATH_MAX is 4096 but we limit the length we store since we have
// limits on the length of the string to compare:
// - Artificial limits for full string comparison.
// - Technical limits for prefix and postfix, using LPM_TRIE that have a 256
//   bytes size limit.
struct binary {
	// length of the path stored in path, this should be < BINARY_PATH_MAX_LEN
	// but can contain negative value in case of copy error.
	// While s16 would be sufficient, 32 bits are handy for alignment.
	__s32 path_length;
	// if end_r contains reversed path postfix
	__u32 reversed;
	// BINARY_PATH_MAX_LEN first bytes of the path
	char path[BINARY_PATH_MAX_LEN];
	// STRING_POSTFIX_MAX_LENGTH last bytes of the path
	char end[STRING_POSTFIX_MAX_LENGTH];
	// STRING_POSTFIX_MAX_LENGTH reversed last bytes of the path
	char end_r[STRING_POSTFIX_MAX_LENGTH];
	// args for the binary
	char args[MAXARGLENGTH];
	// matchBinary bitset for binary
	// NB: everything after and including ->mb_bitset will not be zeroed on a new exec. See
	// binary_reset().
	mbset_t mb_bitset;
}; // All fields aligned so no 'packed' attribute

FUNC_INLINE void
binary_reset(struct binary *b)
{
	// buffer can be written at clone stage with parent's info, if previous path is longer than
	// current, we can have leftovers at the end, so zero out bin structure.
	//
	// Do not zero the ->mb_bitset however, so that it can be inherited if exec() is called.
	// This depends on ->mb_bitset being the last part of the struct.
	memset(b, 0, offsetof(struct binary, mb_bitset));
}

// The execve_map_value is tracked by the TGID of the thread group
// the msg_execve_key.pid. The thread IDs are recorded on the
// fly and sent with every corresponding event.
struct execve_map_value {
	struct msg_execve_key key;
	struct msg_execve_key pkey;
	__u32 flags;
	__u32 nspid;
	struct msg_ns ns;
	struct msg_capabilities caps;
	struct binary bin;
} __attribute__((packed)) __attribute__((aligned(8)));

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct msg_execve_event);
} execve_msg_heap_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct execve_map_value);
} execve_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, __s32);
	__type(value, __s64);
} execve_map_stats SEC(".maps");

enum {
	MAP_STATS_COUNT = 0,
	MAP_STATS_ERROR = 1,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __s32);
	__type(value, struct execve_map_value);
} execve_val SEC(".maps");

struct execve_heap {
	union {
		char pathname[PATHNAME_SIZE];
		char maxpath[4096];
	};
	struct execve_info info;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __s32);
	__type(value, struct execve_heap);
} execve_heap SEC(".maps");

/* The tg_execve_joined_info_map allows to join and combine
 * exec info that is gathered during different hooks
 * through the execve call. The list of current hooks is:
 *   1. kprobe/security_bprm_committing_creds
 *      For details check tg_kp_bprm_committing_creds bpf program.
 *   2. tracepoint/sys_execve
 *      For details see event_execve bpf program.
 *
 * Important: the information stored here is complementary
 * information only, the core logic should not depend on entries
 * of this map to be present.
 *
 * tgid+tid is key as execve is a complex syscall where failures
 * may happen at different levels and hooks, also the thread
 * that triggered and succeeded at execve will be the only new
 * and main thread.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64);
	__type(value, struct execve_info);
} tg_execve_joined_info_map SEC(".maps");

/* The tg_execve_joined_info_map_stats will hold stats about
 * entries and map update errors.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, __s32);
	__type(value, __s64);
} tg_execve_joined_info_map_stats SEC(".maps");

FUNC_INLINE int64_t validate_msg_execve_size(int64_t size)
{
	size_t max = sizeof(struct msg_execve_event);

	/* validate_msg_size() calls need to happen near caller using the
	 * size. Otherwise, depending on kernel version, the verifier may
	 * lose track of the size bounds. Place a compiler barrier here
	 * otherwise clang will likely place this check near other msg
	 * population calls which can be significant distance away resulting
	 * in losing bounds on older kernels where bounds are not tracked
	 * as rigorously.
	 */
	compiler_barrier();
	if (size > max)
		size = max;
	if (size < 1)
		size = offsetof(struct msg_execve_event, buffer);
	compiler_barrier();
	return size;
}

// execve_map_error() will increment the map error counter
FUNC_INLINE void execve_map_error(void)
{
	int one = MAP_STATS_ERROR;
	__s64 *cntr;

	cntr = map_lookup_elem(&execve_map_stats, &one);
	if (cntr)
		*cntr = *cntr + 1;
}

// execve_map_get will look up if pid exists and return it if it does. If it
// does not, it will create a new one and return it.
FUNC_INLINE struct execve_map_value *execve_map_get(__u32 pid)
{
	struct execve_map_value *event;

	event = map_lookup_elem(&execve_map, &pid);
	if (!event) {
		struct execve_map_value *value;
		int err, zero = MAP_STATS_COUNT;
		__s64 *cntr;

		value = map_lookup_elem(&execve_val, &zero);
		if (!value)
			return 0;

		memset(value, 0, sizeof(struct execve_map_value));
		err = map_update_elem(&execve_map, &pid, value, 0);
		if (!err) {
			cntr = map_lookup_elem(&execve_map_stats, &zero);
			if (cntr)
				*cntr = *cntr + 1;
		} else {
			execve_map_error();
		}
		event = map_lookup_elem(&execve_map, &pid);
	}
	return event;
}

FUNC_INLINE struct execve_map_value *execve_map_get_noinit(__u32 pid)
{
	return map_lookup_elem(&execve_map, &pid);
}

FUNC_INLINE void execve_map_delete(__u32 pid)
{
	int err = map_delete_elem(&execve_map, &pid);
	int zero = MAP_STATS_COUNT;
	__s64 *cntr;

	if (!err) {
		cntr = map_lookup_elem(&execve_map_stats, &zero);
		if (cntr)
			*cntr = *cntr - 1;
	} else {
		execve_map_error();
	}
}

// execve_joined_info_map_error() will increment the map error counter
FUNC_INLINE void execve_joined_info_map_error(void)
{
	int one = MAP_STATS_ERROR;
	__s64 *cntr;

	cntr = map_lookup_elem(&tg_execve_joined_info_map_stats, &one);
	if (cntr)
		*cntr = *cntr + 1;
}

FUNC_INLINE void execve_joined_info_map_set(__u64 tid, struct execve_info *info)
{
	int err, zero = MAP_STATS_COUNT;
	__s64 *cntr;

	err = map_update_elem(&tg_execve_joined_info_map, &tid, info, BPF_ANY);
	if (err < 0) {
		/* -EBUSY or -ENOMEM with the help of the cntr error
		 * on the stats map this can be a good indication of
		 * long running workloads and if we have to make the
		 * map size bigger for such cases.
		 */
		execve_joined_info_map_error();
		return;
	}

	cntr = map_lookup_elem(&tg_execve_joined_info_map_stats, &zero);
	if (cntr)
		*cntr = *cntr + 1;
}

/* Clear up some space for next threads */
FUNC_INLINE void execve_joined_info_map_clear(__u64 tid)
{
	int err, zero = MAP_STATS_COUNT;
	__s64 *cntr;

	err = map_delete_elem(&tg_execve_joined_info_map, &tid);
	if (!err) {
		cntr = map_lookup_elem(&tg_execve_joined_info_map_stats, &zero);
		if (cntr)
			*cntr = *cntr - 1;
	}
	/* We don't care here about -ENOENT as there is no guarantee entries
	 * will be present anyway.
	 */
}

/* Returns an execve_info if found. A missing entry is perfectly fine as it
 * could mean we are not interested into storing more information about this task.
 */
FUNC_INLINE struct execve_info *execve_joined_info_map_get(__u64 tid)
{
	return map_lookup_elem(&tg_execve_joined_info_map, &tid);
}

_Static_assert(sizeof(struct execve_map_value) % 8 == 0,
	       "struct execve_map_value should have size multiple of 8 bytes");

#define SENT_FAILED_UNKNOWN 0 // unknown error
#define SENT_FAILED_ENOENT  1 // ENOENT
#define SENT_FAILED_E2BIG   2 // E2BIG
#define SENT_FAILED_EBUSY   3 // EBUSY
#define SENT_FAILED_EINVAL  4 // EINVAL
#define SENT_FAILED_ENOSPC  5 // ENOSPC
#define SENT_FAILED_MAX	    6

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
perf_event_output_update_error_metric(u8 msg_op, long err)
{
	struct kernel_stats *valp;
	__u32 zero = 0;

	valp = map_lookup_elem(&tg_stats_map, &zero);
	if (valp) {
		switch (err) {
		case -2: // ENOENT
			__sync_fetch_and_add(&valp->sent_failed[msg_op][SENT_FAILED_ENOENT], 1);
			break;
		case -7: // E2BIG
			__sync_fetch_and_add(&valp->sent_failed[msg_op][SENT_FAILED_E2BIG], 1);
			break;
		case -16: // EBUSY
			__sync_fetch_and_add(&valp->sent_failed[msg_op][SENT_FAILED_EBUSY], 1);
			break;
		case -22: // EINVAL
			__sync_fetch_and_add(&valp->sent_failed[msg_op][SENT_FAILED_EINVAL], 1);
			break;
		case -28: // ENOSPC
			__sync_fetch_and_add(&valp->sent_failed[msg_op][SENT_FAILED_ENOSPC], 1);
			break;
		default:
			__sync_fetch_and_add(&valp->sent_failed[msg_op][SENT_FAILED_UNKNOWN], 1);
		}
	}
}

FUNC_INLINE void
perf_event_output_metric(void *ctx, u8 msg_op, void *map, u64 flags, void *data, u64 size)
{
	long err;

	err = perf_event_output(ctx, map, flags, data, size);
	if (err < 0)
		perf_event_output_update_error_metric(msg_op, err);
}

#endif //_PROCESS__
