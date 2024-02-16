#include "bpf_enforcer.h"

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

static inline __attribute__((always_inline)) int
do_enforcer(void *ctx)
{
	__u64 id = get_current_pid_tgid();
	struct enforcer_data *data;

	data = map_lookup_elem(&enforcer_data, &id);
	if (!data)
		return 0;

	if (data->signal)
		send_signal(data->signal);

	map_delete_elem(&enforcer_data, &id);
	return data->error;
}

#if defined(__BPF_OVERRIDE_RETURN)

#ifdef __MULTI_KPROBE
#define MAIN "kprobe.multi/enforcer"
#define FUNC kprobe_multi_enforcer
#else
#define MAIN "kprobe/enforcer"
#define FUNC kprobe_enforcer
#endif

__attribute__((section(MAIN), used)) int
FUNC(void *ctx)
{
	long ret;

	ret = do_enforcer(ctx);
	if (ret)
		override_return(ctx, ret);

	return 0;
}

#else /* !__BPF_OVERRIDE_RETURN */

/* Putting security_task_prctl in here to pass contrib/verify/verify.sh test,
 * in normal run the function is set by tetragon dynamically.
 */
__attribute__((section("fmod_ret/security_task_prctl"), used)) long
fmodret_enforcer(void *ctx)
{
	return do_enforcer(ctx);
}

#endif
