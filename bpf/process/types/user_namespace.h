// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Tetragon */

#ifndef __USER_NAMESPACE_H__
#define __USER_NAMESPACE_H__

struct tg_user_namespace {
	__s32 level;
	__u32 uid;
	__u32 gid;
	__u32 ns_inum;
};

#endif
