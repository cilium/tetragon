#include "bpf_killer.h"

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

#ifdef __MULTI_KPROBE
#define MAIN "kprobe.multi/killer"
#else
#define MAIN "kprobe/killer"
#endif

__attribute__((section(MAIN), used)) int
killer(void *ctx)
{
	__u64 id = get_current_pid_tgid();
	struct killer_data *data;

	data = map_lookup_elem(&killer_data, &id);
	if (!data)
		return 0;

	if (data->error)
		override_return(ctx, data->error);
	if (data->signal)
		send_signal(data->signal);

	map_delete_elem(&killer_data, &id);
	return 0;
}
