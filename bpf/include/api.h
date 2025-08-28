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
#include "bpf_helper_defs.h"

/* Events for user space */
static int (*const skb_event_output)(struct __sk_buff *skb, void *map, uint64_t index,
		     const void *data, uint32_t size) __maybe_unused = (void *)BPF_FUNC_perf_event_output;

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
