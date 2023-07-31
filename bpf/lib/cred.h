// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#ifndef __CRED_H__
#define __CRED_H__

#include "user_namespace.h"

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

struct tg_cred {
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
	struct msg_capabilities cap;
	struct tg_userns user_ns;
};

#endif
