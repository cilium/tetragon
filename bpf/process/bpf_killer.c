#include "bpf_killer.h"

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

static inline __attribute__((always_inline)) int
do_killer(void *ctx)
{
	__u64 id = get_current_pid_tgid();
	struct killer_data *data;

	data = map_lookup_elem(&killer_data, &id);
	if (!data)
		return 0;

	if (data->signal)
		send_signal(data->signal);

	map_delete_elem(&killer_data, &id);
	return data->error;
}

#if defined(__BPF_OVERRIDE_RETURN)

#ifdef __MULTI_KPROBE
#define MAIN "kprobe.multi/killer"
#define FUNC kprobe_multi_killer
#else
#define MAIN "kprobe/killer"
#define FUNC kprobe_killer
#endif

__attribute__((section(MAIN), used)) int
FUNC(void *ctx)
{
	long ret;

	ret = do_killer(ctx);
	if (ret)
		override_return(ctx, ret);

	return 0;
}

#else /* !__BPF_OVERRIDE_RETURN */

/* Putting security_task_prctl in here to pass contrib/verify/verify.sh test,
 * in normal run the function is set by tetragon dynamically.
 */
__attribute__((section("fmod_ret/security_task_prctl"), used)) long
fmodret_killer(void *ctx)
{
	return do_killer(ctx);
}

#endif
