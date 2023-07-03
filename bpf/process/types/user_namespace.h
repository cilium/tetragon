// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#ifndef __USER_NAMESPACE_H__
#define __USER_NAMESPACE_H__

struct user_namespace_info_type {
	__s32 level;
	__u32 owner;
	__u32 group;
	__u32 ns_inum;
};

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
/*
	struct msg_capabilities caps;
	struct user_namespace_info_type user_ns;
*/
};

#endif
