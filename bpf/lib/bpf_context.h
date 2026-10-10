// SPDX-License-Identifier: GPL-2.0-only
/* Context detection adapted from Linux's bpf_experimental.h. */

#ifndef __BPF_CONTEXT_H__
#define __BPF_CONTEXT_H__

#include "bpf_core_read.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"

#ifndef __kconfig
#define __kconfig __attribute__((section(".kconfig")))
#endif

/*
 * The preempt_count layout:
 *
 *   legacy:  softirq 8-15, hardirq 16-19, nmi 20-23
 *   new:     softirq 8-15, hardirq disable 16-23, hardirq 24-27, nmi 28-31
 *
 * The new layout comes with HARDIRQ_DISABLE_BITS in the kernel, the nmi field
 * is 4 bits wide with HAS_SEPARATE_PREEMPT_RESCHED_BITS and a single bit
 * (bit 31 is PREEMPT_NEED_RESCHED) otherwise.
 */
#define BPF_CTX_SOFTIRQ_SHIFT  8
#define BPF_CTX_MASK(bits)     ((1UL << (bits)) - 1)
#define BPF_CTX_SOFTIRQ_MASK   (BPF_CTX_MASK(8) << BPF_CTX_SOFTIRQ_SHIFT)
#define BPF_CTX_SOFTIRQ_OFFSET (1UL << BPF_CTX_SOFTIRQ_SHIFT)

#define BPF_CTX_HARDIRQ_MASK_LEGACY (BPF_CTX_MASK(4) << 16)
#define BPF_CTX_NMI_MASK_LEGACY	    (BPF_CTX_MASK(4) << 20)

#define BPF_CTX_HARDIRQ_MASK	 (BPF_CTX_MASK(4) << 24)
#define BPF_CTX_NMI_MASK	 (BPF_CTX_MASK(4) << 28)
#define BPF_CTX_NMI_MASK_NESTING (BPF_CTX_MASK(1) << 28)

/* Defined together with the new preempt_count layout. */
extern unsigned long local_interrupt_disable_state __ksym __weak;
/* Defined only without HAS_SEPARATE_PREEMPT_RESCHED_BITS, single nmi bit. */
extern unsigned int nmi_nesting __ksym __weak;

#ifdef bpf_target_x86
extern const int __preempt_count __ksym __weak;

struct pcpu_hot___local {
	int preempt_count;
} __attribute__((preserve_access_index));

extern struct pcpu_hot___local pcpu_hot __ksym __weak;
#endif

#ifdef bpf_target_s390
extern struct lowcore *bpf_get_lowcore(void) __weak __ksym;
#endif

struct task_struct___preempt_rt {
	int softirq_disable_cnt;
} __attribute__((preserve_access_index));

/* Supported archs: x86,arm64,s390 */
FUNC_INLINE int arch_get_preempt_count(void)
{
#ifdef bpf_target_x86
	if (bpf_ksym_exists(&__preempt_count))
		return *(int *)this_cpu_ptr(&__preempt_count);

	if (bpf_core_field_exists(((struct pcpu_hot___local *)0)->preempt_count))
		return ((struct pcpu_hot___local *)this_cpu_ptr(&pcpu_hot))->preempt_count;
#elif defined(bpf_target_arm64)
	return ((struct task_struct *)get_current_task_btf())->thread_info.preempt.count;
#elif defined(bpf_target_s390)
	return bpf_get_lowcore()->preempt_count;
#endif
	return 0;
}

FUNC_INLINE unsigned long get_preempt_count(void)
{
	unsigned long pc = arch_get_preempt_count();

	/* Set proper softirq context value if present. */
	if (bpf_core_field_exists(((struct task_struct___preempt_rt *)0)->softirq_disable_cnt)) {
		pc &= ~BPF_CTX_SOFTIRQ_MASK;
		pc |= ((struct task_struct___preempt_rt *)get_current_task_btf())->softirq_disable_cnt &
		      BPF_CTX_SOFTIRQ_OFFSET;
	}

	return pc;
}

/*
 * Branch-free !!x for x < 2^32, the barrier keeps the compiler from turning
 * it back into a compare and jump, which forks the verifier state.
 * - x is pc & mask, so it always fits in 32 bits.
 * - If x == 0: 0 + 0xffffffff = 0xffffffff, and shifting right by 32 gives 0.
 * - If x >= 1: the sum is at least 0x100000000, and the shift gives 1. The maximum, 0xffffffff + 0xffffffff, still
 *   shifts to 1.
 */
FUNC_INLINE unsigned long bpf_ctx_nonzero(unsigned long x)
{
	/*
	 * The empty asm makes x opaque to the compiler, so it has to
	 * keep the add and shift. It emits no instructions.
	 */
	asm volatile("" : "+r"(x));
	return (x + 0xffffffffUL) >> 32;
}

/**
 * interrupt_context_level - return interrupt context level
 *
 * Returns the current interrupt context level.
 *  0 - normal context
 *  1 - softirq context
 *  2 - hardirq context
 *  3 - NMI context
 */
FUNC_INLINE unsigned char interrupt_context_level(void)
{
	unsigned long pc = get_preempt_count();
	unsigned long hardirq_mask, nmi_mask;
	unsigned char level = 0;

	if (bpf_ksym_exists(&local_interrupt_disable_state)) {
		hardirq_mask = BPF_CTX_HARDIRQ_MASK;
		nmi_mask = bpf_ksym_exists(&nmi_nesting) ? BPF_CTX_NMI_MASK_NESTING : BPF_CTX_NMI_MASK;
	} else {
		hardirq_mask = BPF_CTX_HARDIRQ_MASK_LEGACY;
		nmi_mask = BPF_CTX_NMI_MASK_LEGACY;
	}

	level += bpf_ctx_nonzero(pc & nmi_mask);
	level += bpf_ctx_nonzero(pc & (nmi_mask | hardirq_mask));
	level += bpf_ctx_nonzero(pc & (nmi_mask | hardirq_mask | BPF_CTX_SOFTIRQ_OFFSET));

	return level;
}

#endif /* __BPF_CONTEXT_H__ */
