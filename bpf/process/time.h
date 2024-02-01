// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __TIME_H__
#define __TIME_H__

/* Parameters used to convert the timespec values: */
#define NSEC_PER_SEC 1000000000L

#define KTIME_MAX     ((s64) ~((u64)1 << 63))
#define KTIME_MIN     (-KTIME_MAX - 1)
#define KTIME_SEC_MAX (KTIME_MAX / NSEC_PER_SEC)
#define KTIME_SEC_MIN (KTIME_MIN / NSEC_PER_SEC)

#define USER_HZ 100 /* some user interfaces are */

static __attribute__((always_inline)) inline s64 timespec64_to_ns(struct timespec64 *ts)
{
	__s64 tv_sec = BPF_CORE_READ(ts, tv_sec);
	long tv_nsec = BPF_CORE_READ(ts, tv_nsec);

	/* Prevent multiplication overflow / underflow */
	if (tv_sec >= KTIME_SEC_MAX)
		return KTIME_MAX;

	if (tv_sec <= KTIME_SEC_MIN)
		return KTIME_MIN;

	return ((s64)tv_sec * NSEC_PER_SEC) + tv_nsec;
}

static __attribute__((always_inline)) inline u64 timens_add_boottime_ns(u64 nsec)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	struct time_namespace *time_ns = BPF_CORE_READ(task, nsproxy, time_ns);
	struct timens_offsets ns_offsets;

	probe_read(&ns_offsets, sizeof(struct timens_offsets), _(&time_ns->offsets));

	return nsec + timespec64_to_ns(&ns_offsets.boottime);
}

static __attribute__((always_inline)) inline u64 div_u64_rem(u64 dividend, u32 divisor, u32 *remainder)
{
	*remainder = dividend % divisor;
	return dividend / divisor;
}

static __attribute__((always_inline)) inline u64 div_u64(u64 dividend, u32 divisor)
{
	u32 remainder;

	return div_u64_rem(dividend, divisor, &remainder);
}

static __attribute__((always_inline)) inline u64 nsec_to_clock_t(u64 x)
{
	return div_u64(x, NSEC_PER_SEC / USER_HZ);
}

#endif /* __TIME_H__ */
