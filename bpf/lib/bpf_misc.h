// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __BPF_MISC_
#define __BPF_MISC_

/* Convenience macro for use with 'asm volatile' blocks */
#define __naked			__attribute__((naked))
#define __clobber_all		"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "memory"
#define __clobber_common	"r0", "r1", "r2", "r3", "r4", "r5", "memory"
#define __imm(name)		[name] "i"(name)
#define __imm_const(name, expr) [name] "i"(expr)
#define __imm_addr(name)	[name] "i"(&name)
#define __imm_ptr(name)		[name] "r"(&name)
#define __imm_insn(name, expr)	[name] "i"(*(long *)&(expr))

#endif /* __BPF_MISC_ */
