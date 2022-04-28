/*
 * When the fullCopy is enabled for argument (fullCopy: true),
 * arguments' data pointer/size couples are stored via
 * full_copy_set function into:
 *
 *   struct msg_generic_kprobe::full_copy.data[8]
 *
 * This will skip the 'actual' data copy to the kprobe's args,
 * but instead it stores special id:
 *
 *   char_buf_fullcopy_arg = -5
 *   original argument size
 *
 * together with following record describing the status of the
 * full copy:
 *
 *   struct data_event_desc {
 *     __s32 error;
 *     __u32 leftover;
 *     struct data_event_id id;
 *   }
 *
 * The 'actual' argument's data is copied via data_event_bytes
 * function and delivered to user space via separate data
 * event(s).
 *
 * The user space side sees following data as argument value:
 *
 *   value                     |  offset
 *   -----------------------------------
 *   char_buf_fullcopy_arg(-5) |       0
 *   orig size                 |       4
 *   struct data_event_desc    |
 *     error                   |       8
 *     leftover                |      12
 *     id                      |      16
 *   next argument data        |      32
 *
 * Based on the 'id' we find the 'actual' argument value
 * from data event.
 *
 * All data events are store on the same cpu ring buffer
 * and *before* the kprobe event is stored. That's because
 * the cpu can't migrate during kprobe bpf program run.
 * The user side can rely on that all its data is already
 * stored.
 */

static inline __attribute__((always_inline)) struct full_copy_data *
fullcopy_data(struct msg_generic_kprobe *msg, int idx)
{
	struct full_copy_data *data;

	asm volatile("%[idx] &= 0x7;\n" ::[idx] "+r"(idx) :);
	data = &msg->full_copy.data[idx];
	return data;
}

static inline __attribute__((always_inline)) int
full_copy(void *ctx, struct bpf_map_def *heap_map,
	  struct bpf_map_def *data_heap)
{
	struct msg_generic_kprobe *msg;
	struct full_copy_data *data;
	int i = 0, zero = 0;
	size_t total;
	char *args;
	int *s;

	msg = map_lookup_elem(heap_map, &zero);
	if (!msg)
		return 0;

	s = (int *)args_off(msg, msg->full_copy.off);
	s[0] = char_buf_fullcopy_arg;
	s[1] = msg->full_copy.bytes;

#ifndef __LARGE_BPF_PROG
#pragma unroll
#endif
	for (i = 0; i < 8; i++) {
		if (i == msg->full_copy.cnt)
			break;

		data = fullcopy_data(msg, i);
		args = args_off(msg, data->off);
		data_event_bytes(ctx, args, data->arg, data->bytes, data_heap);
	}

	total = msg->common.size + generic_kprobe_common_size();
	/* Code movement from clang forces us to inline bounds checks here */
	asm volatile("%[total] &= 0x7fff;\n"
		     "if %[total] < 9000 goto +1\n;"
		     "%[total] = 9000;\n"
		     :
		     : [total] "+r"(total)
		     :);
	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, msg, total);
	return 1;
}
