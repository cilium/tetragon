// SPDX-License-Identifier: GPL-2.0

#ifndef _MSG_COMMON__
#define _MSG_COMMON__

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

#define BPF_F_INDEX_MASK  0xffffffffULL
#define BPF_F_CURRENT_CPU BPF_F_INDEX_MASK

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

#endif // _MSG_COMMON__
