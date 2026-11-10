// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Tetragon */

#include "compiler.h"
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "fmodret.h"

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

/* fmod_ret programs have a fixed BTF target. Load once for each function,
 * then reuse the same program and link for every policy on that function.
 */
const volatile __u64 fmodret_target;

__attribute__((section("fmod_ret/security_task_prctl"), used)) long
shared_fmodret_override(void *ctx)
{
	struct fmodret_key key = {
		.pid_tgid = get_current_pid_tgid(),
		.target = fmodret_target,
	};
	struct fmodret_action *pending, action;
	struct fmodret_binding *binding;

	pending = map_lookup_elem(&fmodret_tasks, &key);
	if (!pending)
		return 0;
	action = *pending;
	map_delete_elem(&fmodret_tasks, &key);

	binding = map_lookup_elem(&fmodret_targets, &action.scope);
	if (!binding || binding->target != fmodret_target || binding->generation != action.generation)
		return 0;

	return (long)action.error;
}

/* Another fmod_ret program can deny before our handler executes. fexit
 * still runs in that case and must discard the unconsumed handoff, so it
 * cannot deny an unrelated invocation by the same thread later.
 */
__attribute__((section("fexit/security_task_prctl"), used)) int
shared_fmodret_cleanup(void *ctx)
{
	struct fmodret_key key = {
		.pid_tgid = get_current_pid_tgid(),
		.target = fmodret_target,
	};

	map_delete_elem(&fmodret_tasks, &key);
	return 0;
}
