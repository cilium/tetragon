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

/* Execution and cred related flags shared with userspace */
#define EXEC_SETUID	 0x01 /* This is a set-user-id execution */
#define EXEC_SETGID	 0x02 /* This is a set-group-id execution */
#define EXEC_FILE_CAPS	 0x04 /* This binary execution gained new capabilities through file capabilities execution */
#define EXEC_SETUID_ROOT 0x08 /* This binary execution gained new privileges through setuid to root execution */
#define EXEC_SETGID_ROOT 0x10 /* This binary execution gained new privileges through setgid to root execution */

/*
 * Check if "a" is a subset of "set".
 * return true if all of the capabilities in "a" are also in "set"
 *	__cap_issubset(0100, 1111) will return true
 * return false if any of the capabilities in "a" are not in "set"
 *	__cap_issubset(1111, 0100) will return false
 */
static inline __attribute__((always_inline)) bool
__cap_issubset(const __u64 a, const __u64 set)
{
	return !(a & ~set);
}

#define __cap_gained(target, source) \
	!__cap_issubset(target, source)

/*
 * We check if it user id is global root. Right now we do not
 * support per user namespace translation, example checking if
 * root in user namespace.
 */
static inline __attribute__((always_inline)) bool
__is_uid_global_root(__u32 uid)
{
	return uid == 0;
}

#endif
