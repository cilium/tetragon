// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Tetragon */

#ifndef BPF_POLICYSTATS_H__
#define BPF_POLICYSTATS_H__

#include "policy_conf.h"

#if defined(GENERIC_KPROBE) || defined(GENERIC_TRACEPOINT) || defined(GENERIC_LSM) || defined(GENERIC_RAWTP) || defined(GENERIC_UPROBE) || defined(GENERIC_USDT) || defined(GENERIC_KRETPROBE) || defined(ALIGNCHECKER)
#define HAS_POLICY_STATS
#endif

/* NB: if you are modifying this enum, you might want to change the proto descriptions for
 * TracingPolicyActionCounters.
 */
enum policy_actions {
	POLICY_INVALID_ACT_ = 0,
	POLICY_POST = 1, /* policy posted an event */
	POLICY_SIGNAL = 2, /* policy sent a signal */
	POLICY_MONITOR_SIGNAL = 3, /* policy did not sent a signal because it was in monitor mode */
	POLICY_OVERRIDE = 4, /* policy overrode a return value */
	POLICY_MONITOR_OVERRIDE = 5, /* policy did not overrode a return value because it was in monitor mode */
	POLICY_NOTIFY_ENFORCER = 6, /* policy notified the enforcer */
	POLICY_MONITOR_NOTIFY_ENFORCER = 7, /* policy did not notify the enforcer because it was in monitor mode */
	POLICY_NACTIONS_,
};

struct policy_stats {
	u64 act_cnt[POLICY_NACTIONS_];
};

#if defined(HAS_POLICY_STATS)
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct policy_stats);
} policy_stats SEC(".maps");

FUNC_INLINE void
policy_stats_update(int act)
{
	struct policy_stats *pstats;
	u32 zero = 0;

	pstats = map_lookup_elem(&policy_stats, &zero);
	if (pstats)
		lock_add(&pstats->act_cnt[act], 1);
}
#else
FUNC_INLINE void
policy_stats_update(int acct)
{
}
#endif

#endif /* BPF_POLICYSTATS_H__ */
