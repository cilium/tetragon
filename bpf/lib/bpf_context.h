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

#define BPF_CTX_PREEMPT_BITS 8
#define BPF_CTX_SOFTIRQ_BITS 8
#define BPF_CTX_HARDIRQ_BITS 4
#define BPF_CTX_NMI_BITS     4

#define BPF_CTX_SOFTIRQ_SHIFT  BPF_CTX_PREEMPT_BITS
#define BPF_CTX_HARDIRQ_SHIFT  (BPF_CTX_SOFTIRQ_SHIFT + BPF_CTX_SOFTIRQ_BITS)
#define BPF_CTX_NMI_SHIFT      (BPF_CTX_HARDIRQ_SHIFT + BPF_CTX_HARDIRQ_BITS)
#define BPF_CTX_MASK(bits)     ((1UL << (bits)) - 1)
#define BPF_CTX_SOFTIRQ_MASK   (BPF_CTX_MASK(BPF_CTX_SOFTIRQ_BITS) << BPF_CTX_SOFTIRQ_SHIFT)
#define BPF_CTX_HARDIRQ_MASK   (BPF_CTX_MASK(BPF_CTX_HARDIRQ_BITS) << BPF_CTX_HARDIRQ_SHIFT)
#define BPF_CTX_NMI_MASK       (BPF_CTX_MASK(BPF_CTX_NMI_BITS) << BPF_CTX_NMI_SHIFT)
#define BPF_CTX_SOFTIRQ_OFFSET (1UL << BPF_CTX_SOFTIRQ_SHIFT)

#ifdef bpf_target_x86
extern const int __preempt_count __ksym __weak;

struct pcpu_hot___local {
	int preempt_count;
} __attribute__((preserve_access_index));

extern struct pcpu_hot___local pcpu_hot __ksym __weak;
#endif

struct task_struct___preempt_rt {
	int softirq_disable_cnt;
} __attribute__((preserve_access_index));

static inline __attribute__((always_inline)) int bpf_ctx_preempt_count(void)
{
#ifdef bpf_target_x86
	if (bpf_ksym_exists(&__preempt_count))
		return *(int *)this_cpu_ptr(&__preempt_count);

	if (bpf_core_field_exists(((struct pcpu_hot___local *)0)->preempt_count))
		return ((struct pcpu_hot___local *)this_cpu_ptr(&pcpu_hot))->preempt_count;
#elif defined(bpf_target_arm64)
	return ((struct task_struct *)get_current_task_btf())->thread_info.preempt.count;
#endif
	return 0;
}

static inline __attribute__((always_inline)) unsigned char interrupt_context_level(void)
{
	unsigned long pc = bpf_ctx_preempt_count();
	unsigned char level = 0;

	if (bpf_core_field_exists(((struct task_struct___preempt_rt *)0)->softirq_disable_cnt)) {
		pc &= ~BPF_CTX_SOFTIRQ_MASK;
		pc |= ((struct task_struct___preempt_rt *)get_current_task_btf())->softirq_disable_cnt &
		      BPF_CTX_SOFTIRQ_OFFSET;
	}

	level += !!(pc & BPF_CTX_NMI_MASK);
	level += !!(pc & (BPF_CTX_NMI_MASK | BPF_CTX_HARDIRQ_MASK));
	level += !!(pc & (BPF_CTX_NMI_MASK | BPF_CTX_HARDIRQ_MASK | BPF_CTX_SOFTIRQ_OFFSET));

	return level;
}

#endif /* __BPF_CONTEXT_H__ */
