// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#ifndef __CRED_H__
#define __CRED_H__

#include "user_namespace.h"

struct cred_info_type {
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
	struct user_namespace_info_type user_ns;
};

#endif
