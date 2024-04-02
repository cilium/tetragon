// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

#ifndef _MSG_COMMON__
#define _MSG_COMMON__

/* msg_common internal flags */
#define MSG_COMMON_FLAG_RETURN		  BIT(0)
#define MSG_COMMON_FLAG_KERNEL_STACKTRACE BIT(1)
#define MSG_COMMON_FLAG_USER_STACKTRACE	  BIT(2)

/* Msg Layout */
struct msg_common {
	__u8 op;
	__u8 flags; // internal flags not exported
	__u8 pad[2];
	__u32 size;
	__u64 ktime;
};

struct msg_test {
	struct msg_common common;
	unsigned long arg0;
	unsigned long arg1;
	unsigned long arg2;
	unsigned long arg3;
} __attribute__((packed));

#ifndef bpf_ntohs
#define bpf_ntohs(x) __builtin_bswap16(x)
#endif

#ifndef bpf_htons
#define bpf_htons(x) __builtin_bswap16(x)
#endif

#ifndef bpf_ntohl
#define bpf_ntohl(x) __builtin_bswap32(x)
#endif

#ifndef bpf_htonl
#define bpf_htonl(x) __builtin_bswap32(x)
#endif

#ifndef bpf_map_def
struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};
#endif

#define BIT(nr)	    (1 << (nr))
#define BIT_ULL(nr) (1ULL << (nr))

#ifdef TETRAGON_BPF_DEBUG
#include <bpf_tracing.h>
#define DEBUG(__fmt, ...) bpf_printk(__fmt, ##__VA_ARGS__)
#else
#define DEBUG(__fmt, ...)
#endif

#endif // _MSG_COMMON__
