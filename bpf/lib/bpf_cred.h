// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Tetragon */

#ifndef __BPF_CRED_
#define __BPF_CRED_

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
}; // All fields aligned so no 'packed' attribute.

// indexes to access msg_capabilities's array (->c) -- should have the same order as the fields above.
enum {
	caps_permitted = 0,
	caps_effective = 1,
	caps_inheritable = 2,
};

struct msg_user_namespace {
	__s32 level;
	__u32 uid;
	__u32 gid;
	__u32 ns_inum;
};

struct msg_cred {
	__u32 uid;
	__u32 gid;
	__u32 suid;
	__u32 sgid;
	__u32 euid;
	__u32 egid;
	__u32 fsuid;
	__u32 fsgid;
	__u32 securebits;
	__u32 pad;
	struct msg_capabilities caps;
	struct msg_user_namespace user_ns;
} __attribute__((packed));

/*
 * TODO: we have msg_cred above that includes the full credentials
 * definition and is used in kprobes.
 * However since we are also moving to use creds for
 * exec events, so let's do it step by step, as we already
 * have the capabilities in execve inside the execve_map and
 * the user space cache, so we start with this minimal
 * credential object that holds only uids/gids, then we follow
 * up by moving the capabilities into it, and make this cred
 * the new storage in execve_map and user space process cache.
 */
struct msg_cred_minimal {
	__u32 uid;
	__u32 gid;
	__u32 suid;
	__u32 sgid;
	__u32 euid;
	__u32 egid;
	__u32 fsuid;
	__u32 fsgid;
	__u32 securebits;
	__u32 pad;
} __attribute__((packed));

#endif
