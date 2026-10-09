/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright Authors of Tetragon */

/*
 * Wire formats shared between the tetragon jvmti agent and tetragon
 * (mirrored in pkg/javaagent/proto.go, keep in sync).
 *
 * All integers are little-endian. Strings are encoded as u16 length
 * followed by the bytes (no NUL).
 */

#ifndef __TETRAGON_JVMTI_PROTO_H__
#define __TETRAGON_JVMTI_PROTO_H__

#include <stdint.h>

#define TG_PROTO_VERSION 1

/*
 * Control channel
 *
 * SOCK_SEQPACKET unix socket created by tetragon, the agent connects to
 * it. Each message starts with struct tg_msg_hdr followed by the payload.
 */

#define TG_MSG_MAX_SIZE (64 * 1024)

enum {
	/* agent -> tetragon: u32 proto_version, str jvm_version */
	TG_MSG_HELLO = 1,
	/* tetragon -> agent: u64 ring size, ring memfd passed with SCM_RIGHTS */
	TG_MSG_RING = 2,
	/*
	 * tetragon -> agent: u32 policy_id, u32 hook_id, u8 kind, u8 pad,
	 *                    u16 nr_methods, str class,
	 *                    nr_methods * { str name, str descriptor }
	 */
	TG_MSG_HOOK_ADD = 3,
	/* tetragon -> agent: u32 policy_id, apply the added hooks */
	TG_MSG_POLICY_COMMIT = 4,
	/* tetragon -> agent: u32 policy_id, remove the policy hooks */
	TG_MSG_POLICY_REMOVE = 5,
	/* agent -> tetragon: u32 seq, i32 status, u32 classes, str error */
	TG_MSG_ACK = 6,
};

/* hook kinds */
enum {
	TG_HOOK_CLASS = 1, /* exact class name (internal form a/b/C) */
	TG_HOOK_PREFIX = 2, /* class name prefix (internal form a/b/) */
};

struct tg_msg_hdr {
	uint16_t type;
	uint16_t flags;
	uint32_t seq;
};

/*
 * Data ring
 *
 * Memfd created by tetragon and passed to the agent. The first page holds
 * struct tg_ring_hdr, the data area follows and has power of 2 size.
 *
 * Producers (java threads) reserve space by CAS on producer_pos, write
 * the record and then commit it by storing (release) the record length
 * into its header. Header with zero length means the record is not
 * committed yet. If the record does not fit before the end of the data
 * area, a padding record is put in front of it.
 *
 * The consumer (tetragon) reads committed records in order, zeroes them
 * and then advances (release) consumer_pos, so the area is always zeroed
 * before producers reuse it.
 *
 * Producers wake up the consumer through the notify futex when
 * consumer_waiting is set.
 */

#define TG_RING_MAGIC 0x4a56544d /* "MTVJ" in little endian */
#define TG_RING_VERSION 1
#define TG_RING_HDR_SIZE 4096

struct tg_ring_hdr {
	uint32_t magic;
	uint32_t version;
	uint64_t data_size;
	uint8_t __pad0[48];
	uint64_t producer_pos; /* offset 64 */
	uint8_t __pad1[56];
	uint64_t consumer_pos; /* offset 128 */
	uint8_t __pad2[56];
	uint64_t dropped; /* offset 192, dropped METHOD_ENTRY records */
	uint64_t dropped_defs; /* offset 200, dropped METHOD_DEF records */
	uint32_t notify; /* offset 208, futex word */
	uint32_t consumer_waiting; /* offset 212 */
};

/* record header, records are 8 bytes aligned */
struct tg_rec_hdr {
	uint32_t len; /* whole record length including header, 0 = not committed */
	uint32_t type;
};

#define TG_REC_ALIGN 8

enum {
	TG_REC_PAD = 1,
	/*
	 * u64 key, u32 policy_id, u32 hook_id, u16 class_len, u16 name_len,
	 * u16 desc_len, u16 pad, class (internal form), name, descriptor
	 */
	TG_REC_METHOD_DEF = 2,
	/* u64 key, u64 ktime, u32 tid, u32 pad */
	TG_REC_METHOD_ENTRY = 3,
};

struct tg_rec_method_def {
	struct tg_rec_hdr hdr;
	uint64_t key;
	uint32_t policy_id;
	uint32_t hook_id;
	uint16_t class_len;
	uint16_t name_len;
	uint16_t desc_len;
	uint16_t __pad;
	/* class, name, descriptor bytes follow */
};

struct tg_rec_method_entry {
	struct tg_rec_hdr hdr;
	uint64_t key;
	uint64_t ktime;
	uint32_t tid;
	uint32_t __pad;
};

#endif /* __TETRAGON_JVMTI_PROTO_H__ */
