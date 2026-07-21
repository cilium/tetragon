// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#pragma once

#ifdef __V511_BPF_PROG

struct rodata_config {
	__u8 ITER_NUM;
	__u8 pad[7];
};

volatile const struct rodata_config rodata_config
	__attribute__((section(".rodata.config"), used));

#define __field(name) name

/*
 * Reconstruct the rodata pointer on each access to prevent the compiler
 * from reusing the pointer across multiple accesses in short
 * succession. This makes branches based on config variables more likely
 * to be predictable using backtracking, since load/deref/branch will be
 * close to each other and the pointer won't be reused across basic
 * blocks.
 */
#define CONFIG(name)                                                         \
	({                                                                   \
		void *out;                                                   \
		asm volatile("%0 = rodata_config ll"                         \
			     : "=r"(out));                                   \
		((volatile const struct rodata_config *)out)->__field(name); \
	})

#else

#define CONFIG(name) 0

#endif /* __V511_BPF_PROG */
