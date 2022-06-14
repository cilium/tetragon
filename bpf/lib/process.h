// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#ifndef _PROCESS__
#define _PROCESS__

#include "hubble_msg.h"
#include "bpf_helpers.h"

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
#define SIZEOF_EVENT 32
#define PADDED_BUFFER                                                          \
	(BUFFER + MAXARGLENGTH + SIZEOF_EVENT + SIZEOF_EVENT + CWD_MAX)
/* This is the usable buffer size for args and filenames. It is calculated
 * as the (BUFFER SIZE - sizeof(parent) - sizeof(curr) but unfortunately
 * preprocess doesn't know types so we do it manually without sizeof().
 */
#define ARGSBUFFER	 (BUFFER - SIZEOF_EVENT - SIZEOF_EVENT)
#define __ASM_ARGSBUFFER 976
#define ARGSBUFFERMASK	 (ARGSBUFFER - 1)
#define MAXARGMASK	 (MAXARG - 1)

/* Msg flags */
#define EVENT_UNKNOWN		    0x00
#define EVENT_EXECVE		    0x01
#define EVENT_EXECVEAT		    0x02
#define EVENT_PROCFS		    0x04
#define EVENT_TRUNC_FILENAME	    0x08
#define EVENT_TRUNC_ARGS	    0x10
#define EVENT_TASK_WALK		    0x20
#define EVENT_MISS		    0x40
#define EVENT_NEEDS_AUID	    0x80
#define EVENT_ERROR_FILENAME	    0x100
#define EVENT_ERROR_ARGS	    0x200
#define EVENT_NEEDS_CWD		    0x400
#define EVENT_NO_CWD_SUPPORT	    0x800
#define EVENT_ROOT_CWD		    0x1000
#define EVENT_ERROR_CWD		    0x2000
#define EVENT_CLONE		    0x4000
#define EVENT_ERROR_SOCK	    0x8000
#define EVENT_DOCKER_NAME_ERR	    0x010000
#define EVENT_DOCKER_KN_ERR	    0x020000
#define EVENT_DOCKER_SUBSYSCGRP_ERR 0x040000
#define EVENT_DOCKER_SUBSYS_ERR	    0x080000
#define EVENT_DOCKER_CGROUPS_ERR    0x100000
// #define EVENT_ERROR_MOUNT_POINTS    0x200000 // (deprecated)
#define EVENT_ERROR_PATH_COMPONENTS 0x400000
#define EVENT_DATA_FILENAME	    0x800000
#define EVENT_DATA_ARGS		    0x1000000

#define EVENT_COMMON_FLAG_CLONE 0x01

/* Docker IDs are unique at first 12 characters, but we want to get
 * 12chars plus any extra prefix used by the container environment.
 * Minikube for example prepends 'docker-' to the id. So lets copy
 * 32B and assume at least 12B of it is ID info.
 */
#define DOCKER_ID_LENGTH 128

struct msg_execve_key {
	__u32 pid;
	__u8 pad[4];
	__u64 ktime;
} __attribute__((packed));

/* process information
 *
 * Manually linked to ARGSBUFFER and PADDED_BUFFER if this changes then please
 * also change SIZEOF_EVENT.
 */
struct msg_process {
	__u32 size;
	__u32 pid;
	__u32 nspid;
	__u32 uid;
	__u32 auid;
	__u32 flags;
	__u64 ktime;
	char *args;
};

/* msg_clone_event holds only the necessary fields to construct a new entry from
 * the parent after a clone() event.
 */
struct msg_clone_event {
	struct msg_common common;
	struct msg_execve_key parent;
	__u32 pid;
	__u32 nspid;
	__u32 flags;
	__u64 ktime;
} __attribute__((packed));

// NB: in some cases we want to access the capabilities via an array to simplify the BPF code, which is why we define it as a union.
struct msg_capabilities {
	union {
		struct {
			__u64 permitted;
			__u64 effective;
			__u64 inheritable;
		};
		__u64 c[3];
	};
};

// indexes to access msg_capabilities's array (->c) -- should have the same order as the fields above.
enum {
	caps_permitted = 0,
	caps_effective = 1,
	caps_inheritable = 2,
};

struct exit_info {
	__u32 code;
	__u32 pad;
};

struct msg_exit {
	struct msg_common common;
	struct msg_execve_key current;
	struct exit_info info;
};

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
};

struct msg_k8s {
	__u32 net_ns;
	__u32 cid;
	__u64 cgrpid;
	char docker_id[DOCKER_ID_LENGTH];
} __attribute__((packed));

struct msg_execve_event {
	struct msg_common common;
	struct msg_k8s kube;
	struct msg_execve_key parent;
	__u64 parent_flags;
	struct msg_capabilities caps;
	struct msg_ns ns;
	/* if add anything above please also update the args of
	 * validate_msg_execve_size() in bpf_execve_event.c */
	union {
		struct msg_process process;
		char buffer[PADDED_BUFFER];
	};
} __attribute__((packed));

struct execve_map_value {
	struct msg_execve_key key;
	struct msg_execve_key pkey;
	__u32 flags;
	__u32 nspid;
	__u32 binary;
	__u32 pad;
	struct msg_ns ns;
	struct msg_capabilities caps;
} __attribute__((packed)) __attribute__((aligned(8)));

struct bpf_map_def __attribute__((section("maps"), used))
execve_msg_heap_map = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct msg_execve_event),
	.max_entries = 1,
};

struct bpf_map_def __attribute__((section("maps"), used)) execve_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct execve_map_value),
	.max_entries = 32768,
};

struct bpf_map_def __attribute__((section("maps"), used)) execve_map_stats = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__s32),
	.value_size = sizeof(__s64),
	.max_entries = 1,
};

struct bpf_map_def __attribute__((section("maps"), used)) execve_val = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__s32),
	.value_size = sizeof(struct execve_map_value),
	.max_entries = 1,
};

struct execve_heap {
	union {
		char pathname[256];
		char maxpath[4096];
	};
};

struct bpf_map_def __attribute__((section("maps"), used)) execve_heap = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(__s32),
	.value_size = sizeof(struct execve_heap),
	.max_entries = 1,
};

static inline __attribute__((always_inline)) int64_t
validate_msg_execve_size(int64_t size)
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

// execve_map_get will look up if pid exists and return it if it does. If it
// does not, it will create a new one and return it.
static inline __attribute__((always_inline)) struct execve_map_value *
execve_map_get(__u32 pid)
{
	struct execve_map_value *event;

	event = map_lookup_elem(&execve_map, &pid);
	if (!event) {
		struct execve_map_value *value;
		int err, zero = 0;
		__s64 *cntr;

		value = map_lookup_elem(&execve_val, &zero);
		if (!value)
			return 0;

		memset(value, 0, sizeof(struct execve_map_value));
		err = map_update_elem(&execve_map, &pid, value, 0);
		if (!err && (cntr = map_lookup_elem(&execve_map_stats, &zero)))
			*cntr = *cntr + 1;
		event = map_lookup_elem(&execve_map, &pid);
	}
	return event;
}

static inline __attribute__((always_inline)) struct execve_map_value *
execve_map_get_noinit(__u32 pid)
{
	return map_lookup_elem(&execve_map, &pid);
}

static inline __attribute__((always_inline)) void execve_map_delete(__u32 pid)
{
	int err = map_delete_elem(&execve_map, &pid);
	int zero = 0;
	__s64 *cntr;
	if (!err && (cntr = map_lookup_elem(&execve_map_stats, &zero)))
		*cntr = *cntr - 1;
}

_Static_assert(sizeof(struct execve_map_value) % 8 == 0,
	       "struct execve_map_value should have size multiple of 8 bytes");
#endif //_PROCESS__
