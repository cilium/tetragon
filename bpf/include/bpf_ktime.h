/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __BPF_KTIME_H__
#define __BPF_KTIME_H__

FUNC_INLINE __u64 tg_get_ktime(void)
{
#ifdef __LARGE_BPF_PROG
	return (bpf_core_type_exists(btf_bpf_ktime_get_boot_ns)) ? (ktime_get_boot_ns()) : (ktime_get_ns());
#else
	return ktime_get_ns();
#endif
}

#endif /* __BPF_KTIME_H__ */
