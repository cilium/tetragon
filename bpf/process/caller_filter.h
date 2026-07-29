#ifndef __CALLER_FILTER_H__
#define __CALLER_FILTER_H__

#include "errmetrics.h"

#define BUILD_ID_SIZE	  20
#define MAX_MATCH_CALLERS 5
#define MATCH_CALLER_SIZE 24

enum caller_filter_result {
	CALLER_FILTER_REJECT,
	CALLER_FILTER_ACCEPT,
	CALLER_FILTER_CONTINUE,
};

#ifdef __LARGE_BPF_PROG
FUNC_INLINE bool generic_filter_caller_stack_entry_matches(struct msg_generic_kprobe *e, __u32 i,
							   __u64 match_start, __u64 match_end,
							   void *match_build_id)
{
	if (e->user_stack[i].status != BPF_STACK_BUILD_ID_VALID)
		return false;
	if (e->user_stack[i].ip < match_start || e->user_stack[i].ip > match_end)
		return false;
	return memcmp(e->user_stack[i].build_id, match_build_id,
		      sizeof(e->user_stack[i].build_id)) == 0;
}

FUNC_INLINE enum caller_filter_result generic_filter_caller_match_one(struct msg_generic_kprobe *e, __u32 *f,
								      __u32 seloff, long matchoff,
								      __u32 ret_entries)
{
	long build_id_array_start;
	__u32 i, match_depth, match_build_id_ref;
	__u64 match_start, match_end;
	void *match_build_id;

	/* The verifier loses the upper bound check, so apply a mask to each iteration */
	asm volatile("%[ret_entries] &= 0x1f;\n"
		     : [ret_entries] "+r"(ret_entries));

	match_depth = *(__u32 *)((__u64)f + (matchoff & INDEX_MASK));
	if (match_depth >= MAX_STACK_DEPTH)
		return CALLER_FILTER_REJECT;

	match_build_id_ref = *(__u32 *)((__u64)f + ((matchoff + 4) & INDEX_MASK));
	match_start = *(__u64 *)((__u64)f + ((matchoff + 8) & INDEX_MASK));
	match_end = *(__u64 *)((__u64)f + ((matchoff + 16) & INDEX_MASK));

	if (match_start == 0 && match_end == 0)
		return CALLER_FILTER_ACCEPT;

	/* Starting from the selector, we need to skip both the overall and the buildID u32 length fields */
	build_id_array_start = seloff + 4 + 4;
	match_build_id =
		(void *)((__u64)f +
			 ((build_id_array_start + BUILD_ID_SIZE * match_build_id_ref) & INDEX_MASK));

	if (match_depth == 0) {
		if (CONFIG(ITER_NUM)) {
			bpf_for(i, 1, MAX_STACK_DEPTH)
			{
				if (i >= ret_entries)
					return CALLER_FILTER_REJECT;
				if (generic_filter_caller_stack_entry_matches(
					    e, i, match_start, match_end, match_build_id))
					return CALLER_FILTER_CONTINUE; /* found a match for this entry, continue with the next */
			}
			return CALLER_FILTER_REJECT;
		}

		for (i = 1; i < MAX_STACK_DEPTH; i++) {
			if (i >= ret_entries)
				return CALLER_FILTER_REJECT;
			if (generic_filter_caller_stack_entry_matches(
				    e, i, match_start, match_end, match_build_id))
				return CALLER_FILTER_CONTINUE; /* found a match for this entry, continue with the next */
		}
		return CALLER_FILTER_REJECT;
	}

	match_depth &= MAX_STACK_DEPTH - 1;
	if (match_depth >= ret_entries)
		return CALLER_FILTER_REJECT;

	return generic_filter_caller_stack_entry_matches(e, match_depth, match_start, match_end,
							 match_build_id)
		       ? CALLER_FILTER_CONTINUE
		       : CALLER_FILTER_REJECT;
}

FUNC_INLINE enum caller_filter_result generic_filter_caller(void *ctx, struct msg_generic_kprobe *e, __u32 *f, __u32 seloff)
{
	long matchoff;
	enum caller_filter_result ret;
	__u32 callerlen, k, ret_entries;

	/* seloff is the offset of the matchCallers section for the current
	 * selector
	 *
	 * now pointing at the matchCallers section:
	 * [length u32][CALoffset u32][BuildID1 [20]byte]...[BuildIDn][CAL1]...[CALn]
	 */
	callerlen = *(__u32 *)((__u64)f + (seloff & INDEX_MASK));
	if (callerlen <= 8) /* no matchCallers configured */
		return CALLER_FILTER_ACCEPT;

	matchoff = seloff + 4; /* skip length field */
	matchoff += *(__u32 *)((__u64)f + (matchoff & INDEX_MASK)); /* skip matchCaller BuildIDs */

	/* Pre-check the cached value so that the verifier can merge it with the
	 * bounds applied to a fresh get_stack() result.
	 */
	if (e->user_stack_ret < -MAX_ERRNO || e->user_stack_ret > sizeof(e->user_stack))
		return CALLER_FILTER_REJECT;

	if (e->user_stack_ret == 0)
		e->user_stack_ret = with_errmetrics(get_stack, ctx, &e->user_stack, sizeof(e->user_stack),
						    BPF_F_USER_STACK | BPF_F_USER_BUILD_ID);

	if (e->user_stack_ret <= 0 || e->user_stack_ret > sizeof(e->user_stack))
		return CALLER_FILTER_REJECT;

	ret_entries = e->user_stack_ret / sizeof(struct bpf_stack_build_id);
	if (ret_entries > MAX_STACK_DEPTH)
		return CALLER_FILTER_REJECT;

	if (CONFIG(ITER_NUM)) {
		bpf_for(k, 0, MAX_MATCH_CALLERS)
		{
			if (matchoff >= callerlen + seloff)
				return CALLER_FILTER_ACCEPT;

			ret = generic_filter_caller_match_one(e, f, seloff, matchoff, ret_entries);
			if (ret != CALLER_FILTER_CONTINUE)
				return ret;

			matchoff += MATCH_CALLER_SIZE;
		}

		return matchoff >= callerlen + seloff ? CALLER_FILTER_ACCEPT : CALLER_FILTER_REJECT;
	}
	for (k = 0; k < MAX_MATCH_CALLERS; k++) {
		if (matchoff >= callerlen + seloff)
			return CALLER_FILTER_ACCEPT; /* no more matchCallers, all previous matchCallers matched */

		ret = generic_filter_caller_match_one(e, f, seloff, matchoff, ret_entries);
		if (ret != CALLER_FILTER_CONTINUE)
			return ret;

		matchoff += MATCH_CALLER_SIZE; /* goto next matchCaller entry */
	}

	return matchoff >= callerlen + seloff ? CALLER_FILTER_ACCEPT : CALLER_FILTER_REJECT;
}
#endif /* __LARGE_BPF_PROG */

#endif /* __CALLER_FILTER_H__ */
