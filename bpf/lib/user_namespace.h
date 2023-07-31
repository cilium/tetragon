// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#ifndef __USER_NAMESPACE_H__
#define __USER_NAMESPACE_H__

struct tg_userns {
	__s32 level;
	__u32 owner;
	__u32 group;
	__u32 ns_inum;
};

#endif
