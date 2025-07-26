#ifndef __BPF_API__
#define __BPF_API__

/* Note:
 *
 * This file can be included into eBPF kernel programs. It contains
 * a couple of useful helper functions, map/section ABI (bpf_elf.h),
 * misc macros and some eBPF specific LLVM built-ins.
 */
#include "bpf_elf.h"

#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#define TC_ACT_RECLASSIFY       1
#define TC_ACT_SHOT             2
#define TC_ACT_PIPE             3
#define TC_ACT_STOLEN           4
#define TC_ACT_QUEUED           5
#define TC_ACT_REPEAT           6
#define TC_ACT_REDIRECT         7
#endif
#define TC_ACT_UNSPEC		-1

/** Misc macros. */

#ifndef __stringify
# define __stringify(X)		#X
#endif

#ifndef __maybe_unused
# define __maybe_unused		__attribute__((__unused__))
#endif

#ifndef offsetof
# define offsetof(TYPE, MEMBER)	__builtin_offsetof(TYPE, MEMBER)
#endif

#ifndef likely
# define likely(X)		__builtin_expect(!!(X), 1)
#endif

#ifndef unlikely
# define unlikely(X)		__builtin_expect(!!(X), 0)
#endif

#ifndef __inline__
# define __inline__		__attribute__((always_inline))
#endif

/** Section helper macros. */

#ifndef __section
# define __section(NAME)						\
	__attribute__((section(NAME), used))
#endif

#ifndef __section_tail
# define __section_tail(ID, KEY)					\
	__section(__stringify(ID) "/" __stringify(KEY))
#endif

#ifndef __section_cls_entry
# define __section_cls_entry						\
	__section(ELF_SECTION_CLASSIFIER)
#endif

#ifndef __section_act_entry
# define __section_act_entry						\
	__section(ELF_SECTION_ACTION)
#endif

#ifndef __section_license
# define __section_license						\
	__section(ELF_SECTION_LICENSE)
#endif

#ifndef __section_maps
# define __section_maps							\
	__section(ELF_SECTION_MAPS)
#endif

/** Declaration helper macros. */

#ifndef BPF_LICENSE
# define BPF_LICENSE(NAME)						\
	char ____license[] __section_license = NAME
#endif

/** Classifier helper */

#ifndef BPF_H_DEFAULT
# define BPF_H_DEFAULT	-1
#endif

/** BPF helper functions for tc. Individual flags are in linux/bpf.h */

#ifndef BPF_FUNC
# define BPF_FUNC(NAME, ...)						\
	(* NAME)(__VA_ARGS__) __maybe_unused = (void *) BPF_FUNC_##NAME
#endif

#ifndef BPF_FUNC2
# define BPF_FUNC2(NAME, ...)						\
	(* NAME)(__VA_ARGS__) __maybe_unused
#endif

/* Map access/manipulation */
static void *BPF_FUNC(map_lookup_elem, void *map, const void *key);
static int BPF_FUNC(map_update_elem, void *map, const void *key,
		    const void *value, uint32_t flags);
static int BPF_FUNC(map_delete_elem, void *map, const void *key);

/* Memory reads */
static int BPF_FUNC(probe_read, void *dst, uint32_t size, const void *src);
static int BPF_FUNC(probe_read_str, void *dst, int size, const void *src);
static int BPF_FUNC(probe_read_kernel, void *dst, uint32_t size, const void *src);
static int BPF_FUNC(probe_read_user, void *dst, uint32_t size, const void *src);

/* Time access */
static uint64_t BPF_FUNC(ktime_get_ns);
static uint64_t BPF_FUNC(ktime_get_boot_ns);
static uint64_t BPF_FUNC(ktime_get_coarse_ns);
static uint64_t BPF_FUNC(jiffies64);

/* Platform */
static uint64_t BPF_FUNC(get_numa_node_id);

/* Timer Callbacks */
static long BPF_FUNC(timer_init, struct bpf_timer *timer, void *map, uint64_t flags);
static long BPF_FUNC(timer_set_callback, struct bpf_timer *timer, void *callback_fun);
static long BPF_FUNC(timer_start, struct bpf_timer *timer, uint64_t nsecs, uint64_t flags);
static long BPF_FUNC(timer_cancel, struct bpf_timer *timer);

/* Sockets */
static uint64_t BPF_FUNC(get_socket_cookie, void *ctx);

static struct bpf_sock *BPF_FUNC(sk_lookup_tcp, void *ctx, struct bpf_sock_tuple *tuple, u32 tuple_size, u64 netns, u64 flags);
static struct bpf_sock *BPF_FUNC(sk_lookup_udp, void *ctx, struct bpf_sock_tuple *tuple, u32 tuple_size, u64 netns, u64 flags);
static uint64_t BPF_FUNC(sk_release, void *sock);
static struct bpf_sock *BPF_FUNC(sk_fullsock, struct bpf_sock *sk);
static struct bpf_tcp_sock *BPF_FUNC(tcp_sock, struct bpf_sock *sk);
static struct bpf_sock *BPF_FUNC(get_listener_sock, struct bpf_sock *sk);
static struct bpf_sock *BPF_FUNC(skc_lookup_tcp, void *ctx, struct bpf_sock_tuple *tuple, u32 tuple_size, u64 netns, u64 flags);
static void *BPF_FUNC(sk_storage_get, struct bpf_map *map, void *sk, void *value, u64 flags);
static void *BPF_FUNC(sk_storage_delete, struct bpf_map *map, void *sk);
static struct tcp6_sock *BPF_FUNC(skc_to_tcp6_sock, void *sk);
static struct tcp_sock *BPF_FUNC(skc_to_tcp_sock, void *sk);
static struct tcp_timewait_sock *BPF_FUNC(skc_to_tcp_timewait_sock, void *sk);
static struct tcp_request_sock *BPF_FUNC(skc_to_tcp_request_sock, void *sk);
static struct udp6_sock *BPF_FUNC(skc_to_udp6_sock, void *sk);
static struct socket *BPF_FUNC(sock_from_file, struct file *file);

/* Debugging */
__attribute__((__format__(__printf__, 1, 0)))
static void BPF_FUNC(trace_printk, const char *fmt, int fmt_size, ...);
static long BPF_FUNC(trace_vprintk, const char *fmt, __u32 fmt_size, const void *data, __u32 data_len);


/* Random numbers */
static uint32_t BPF_FUNC(get_prandom_u32);

/* Tail calls */
static void BPF_FUNC(tail_call, void *ctx, void *map, uint32_t index);

/* System helpers */
static uint32_t BPF_FUNC(get_smp_processor_id);

/* Packet misc meta data */
static uint32_t BPF_FUNC(get_cgroup_classid, struct __sk_buff *skb);
static uint32_t BPF_FUNC(get_route_realm, struct __sk_buff *skb);
static uint32_t BPF_FUNC(get_hash_recalc, struct __sk_buff *skb);
static uint32_t BPF_FUNC(set_hash_invalid, struct __sk_buff *skb);

static int BPF_FUNC(skb_under_cgroup, void *map, uint32_t index);

/* Packet redirection */
static int BPF_FUNC(redirect, int ifindex, uint32_t flags);
static int BPF_FUNC(clone_redirect, struct __sk_buff *skb, int ifindex,
		    uint32_t flags);

/* Packet manipulation */
static int BPF_FUNC(skb_load_bytes_relative, struct __sk_buff *skb, uint32_t off,
		    void *to, uint32_t len, uint32_t hdr);
static int BPF_FUNC(skb_load_bytes, struct __sk_buff *skb, uint32_t off,
		    void *to, uint32_t len);
static int BPF_FUNC(skb_store_bytes, struct __sk_buff *skb, uint32_t off,
		    const void *from, uint32_t len, uint32_t flags);

static int BPF_FUNC(l3_csum_replace, struct __sk_buff *skb, uint32_t off,
		    uint32_t from, uint32_t to, uint32_t flags);
static int BPF_FUNC(l4_csum_replace, struct __sk_buff *skb, uint32_t off,
		    uint32_t from, uint32_t to, uint32_t flags);
static int BPF_FUNC(csum_diff, void *from, uint32_t from_size, void *to,
		    uint32_t to_size, uint32_t seed);

static int BPF_FUNC(skb_change_type, struct __sk_buff *skb, uint32_t type);
static int BPF_FUNC(skb_change_proto, struct __sk_buff *skb, uint32_t proto,
		    uint32_t flags);
static int BPF_FUNC(skb_change_tail, struct __sk_buff *skb, uint32_t nlen,
		    uint32_t flags);
static int BPF_FUNC(skb_adjust_room, struct __sk_buff *skb, int32_t len_diff,
		    uint32_t mode, uint64_t flags);
static int BPF_FUNC(skb_pull_data, struct __sk_buff *skb, uint32_t len);

/* Packet vlan encap/decap */
static int BPF_FUNC(skb_vlan_push, struct __sk_buff *skb, uint16_t proto,
		    uint16_t vlan_tci);
static int BPF_FUNC(skb_vlan_pop, struct __sk_buff *skb);

/* Packet tunnel encap/decap */
static int BPF_FUNC(skb_get_tunnel_key, struct __sk_buff *skb,
		    struct bpf_tunnel_key *to, uint32_t size, uint32_t flags);
static int BPF_FUNC(skb_set_tunnel_key, struct __sk_buff *skb,
		    const struct bpf_tunnel_key *from, uint32_t size,
		    uint32_t flags);

static int BPF_FUNC(skb_get_tunnel_opt, struct __sk_buff *skb,
		    void *to, uint32_t size);
static int BPF_FUNC(skb_set_tunnel_opt, struct __sk_buff *skb,
		    const void *from, uint32_t size);

/* Events for user space */
static int BPF_FUNC2(skb_event_output, struct __sk_buff *skb, void *map, uint64_t index,
		     const void *data, uint32_t size) = (void *)BPF_FUNC_perf_event_output;

/* Sockops and SK_MSG helpers */
static int BPF_FUNC(sock_map_update, struct bpf_sock_ops *skops, void *map, uint32_t key,  uint64_t flags);
static int BPF_FUNC(sock_hash_update, struct bpf_sock_ops *skops, void *map, void *key,  uint64_t flags);
static int BPF_FUNC(msg_redirect_hash, struct sk_msg_md *md, void *map, void *key, uint64_t flags);
static int BPF_FUNC(msg_pull_data, struct sk_msg_md *md, __u32 start, __u32 end, __u64 flags);
static int BPF_FUNC(msg_apply_bytes, struct sk_msg_md *md, __u32 bytes);
static int BPF_FUNC(msg_cork_bytes, struct sk_msg_md *md, __u32 bytes);

static int BPF_FUNC(fib_lookup, void *ctx, struct bpf_fib_lookup *params, uint32_t plen, uint32_t flags);


/* Current Process Info */
static uint64_t BPF_FUNC(get_current_task);
static uint64_t BPF_FUNC(get_current_task_btf);
static uint64_t BPF_FUNC(get_current_cgroup_id);
static uint64_t BPF_FUNC(get_current_ancestor_cgroup_id, int ancestor_level);
static uint64_t BPF_FUNC(get_current_uid_gid);
static uint64_t BPF_FUNC(get_current_pid_tgid);

static int BPF_FUNC(get_current_comm, char *buf, uint32_t size);

static int BPF_FUNC(send_signal, uint32_t sig);
static int BPF_FUNC(override_return, void *regs, uint64_t rc);
static long BPF_FUNC(get_stackid, void *ctx, void *map, uint64_t flags);
static long BPF_FUNC(loop, __u32 nr_loops, void *callback_fn, void *callback_ctx, __u64 flags);
static __u64 BPF_FUNC(get_attach_cookie, void *ctx);

/* Perf and Rignbuffer */
static int BPF_FUNC(perf_event_output, void *ctx, void *map, uint64_t flags, void *data, uint64_t size);

static int BPF_FUNC(get_stack, void *ctx, void *buf, uint32_t size, uint64_t flags);
static long BPF_FUNC(ringbuf_output, void *data, uint64_t size, uint64_t flags);
static void *BPF_FUNC(ringbuf_reserve, void *ringbuf, uint64_t size, uint64_t flags);
static void BPF_FUNC(ringbuf_submit, void *data, uint64_t flags);
static void BPF_FUNC(ringbuf_discard, void *data, uint64_t flags);
static long BPF_FUNC(ringbuf_query, void *ringbuf, uint64_t flags);

static long BPF_FUNC(ringbuf_reserve_dynptr, void *ringbuf, uint32_t size, uint64_t flags, struct bpf_dynptr *ptr);
static void BPF_FUNC(ringbuf_submit_dynptr, struct bpf_dynptr *ptr, uint64_t flags);
static void BPF_FUNC(ringbuf_discard_dynptr, struct bpf_dynptr *ptr, uint64_t flags);

static long BPF_FUNC(dynptr_from_mem, void *data, uint32_t size, uint64_t flags, struct bpf_dynptr *ptr);
static long BPF_FUNC(dynptr_read, void *dst, uint32_t len, const struct bpf_dynptr *src, uint32_t offset, uint64_t flags);
static long BPF_FUNC(dynptr_write, const struct bpf_dynptr *dst, uint32_t offset, void *src, uint32_t len, uint64_t flags);
static void BPF_FUNC(dynptr_data, const struct bpf_dynptr *ptr, uint32_t offset, uint32_t len);

static long BPF_FUNC(sock_ops_cb_flags_set, struct bpf_sock_ops *bpf_sock, int argval);

/* LSM */
static long BPF_FUNC(ima_file_hash, struct file *file, void *dst, uint32_t size);
static long BPF_FUNC(ima_inode_hash, struct inode *inode, void *dst, uint32_t size);

static int BPF_FUNC(seq_write, struct seq_file *m, const void *data, uint32_t len);

/** LLVM built-ins, mem*() routines work for constant size */

#ifndef memset
# define memset(s, c, n)	__builtin_memset((s), (c), (n))
#endif

#ifndef memcpy
# define memcpy(d, s, n)	__builtin_memcpy((d), (s), (n))
#endif

#ifndef memmove
# define memmove(d, s, n)	__builtin_memmove((d), (s), (n))
#endif

/* FIXME: __builtin_memcmp() is not yet fully useable unless llvm bug
 * https://llvm.org/bugs/show_bug.cgi?id=26218 gets resolved. Also
 * this one would generate a reloc entry (non-map), otherwise.
 */
#if 0
#ifndef memcmp
# define memcmp(a, b, n)	__builtin_memcmp((a), (b), (n))
#endif
#endif

/**
 * atomic add is support from before 4.19 on both arm and x86,
 * x86 has other atomics support from 5.11, arm from 5.17
 */
#if defined(__TARGET_ARCH_arm64) && defined(__V61_BPF_PROG)
#define __HAS_ALL_ATOMICS 1
#endif
#if defined(__TARGET_ARCH_x86) && defined(__V511_BPF_PROG)
#define __HAS_ALL_ATOMICS 1
#endif

#define lock_add(ptr, val)	((void)__sync_fetch_and_add(ptr, val))

#ifdef __HAS_ALL_ATOMICS
# define lock_or(ptr, val)	((void)__sync_fetch_and_or(ptr, val))
# define lock_and(ptr, val)	((void)__sync_fetch_and_and(ptr, val))
#else
# define lock_or(ptr, val)	(*(ptr) |= val)
# define lock_and(ptr, val)	(*(ptr) &= val)
#endif

#endif /* __BPF_API__ */
