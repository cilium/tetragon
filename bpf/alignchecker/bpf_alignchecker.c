#define ALIGNCHECKER

#include "include/vmlinux.h"
#include "include/api.h"
#include "lib/hubble_msg.h"
#include "process/retprobe_map.h"
#include "process/types/basic.h"

/* DECLARE declares a unique usage of the union or struct 'x' on the stack.
 *
 * To prevent compiler from optimizing away the var, we pass a reference
 * to the var to a BPF helper function which accepts a reference as
 * an argument.
 *
 * We make the variable here pointer in order to fit all structs
 * even in this case object files contain all the required information
 */
#define DECLARE(datatype, x, iter)                                             \
	{                                                                      \
		datatype x *s##iter = 0;                                       \
		trace_printk("%p", 1, &s##iter);                               \
		iter++;                                                        \
	}

/* This function is a placeholder for C struct definitions shared with Go,
 * it is never executed.
 */
int main(void)
{
	int iter = 0;

	// from perf_event_output
	DECLARE(struct, msg_generic_kprobe, iter);
	DECLARE(struct, msg_execve_event, iter);
	DECLARE(struct, msg_exit, iter);
	DECLARE(struct, msg_test, iter);
	DECLARE(struct, msg_cgroup_event, iter);

	// from maps
	DECLARE(struct, event, iter);
	DECLARE(struct, msg_execve_key, iter);
	DECLARE(struct, execve_map_value, iter);
	DECLARE(struct, event_config, iter);
	DECLARE(struct, tetragon_conf, iter);
	DECLARE(struct, cgroup_tracking_value, iter);

	return 0;
}
