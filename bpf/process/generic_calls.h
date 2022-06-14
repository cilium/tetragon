#define MAX_TOTAL 9000

static inline __attribute__((always_inline)) int
generic_process_event0(struct pt_regs *ctx, struct bpf_map_def *heap_map,
		       struct bpf_map_def *map, struct bpf_map_def *tailcals,
		       struct bpf_map_def *config_map)
{
	struct execve_map_value *enter;
	struct msg_generic_kprobe *e;
	unsigned long a0, a1, a2, a3, a4;
	struct event_config *config;
	bool walker = 0;
	__u32 ppid;
	int zero = 0;
	/* total is used as a pointer offset so we want type to match
	 * pointer type in order to avoid bit shifts.
	 */
	long ty, total = 0;

	enter = event_find_curr(&ppid, 0, &walker);
	if (!enter)
		return 0;

	// get e again to help verifier
	e = map_lookup_elem(heap_map, &zero);
	if (!e)
		return 0;

	config = map_lookup_elem(config_map, &zero);
	if (!config)
		return 0;

	a0 = e->a0;
	a1 = e->a1;
	a2 = e->a2;
	a3 = e->a3;
	a4 = e->a4;

	e->common.flags = 0;
	e->common.pad[0] = 0;
	e->common.pad[1] = 0;
	e->common.size = 0;
	e->common.ktime = ktime_get_ns();

	e->current.pad[0] = 0;
	e->current.pad[1] = 0;
	e->current.pad[2] = 0;
	e->current.pad[3] = 0;

	e->id = config->func_id;
	e->thread_id = retprobe_map_get_key(ctx);

	/* If return arg is needed mark retprobe */
#ifdef GENERIC_KPROBE
	ty = config->argreturn;
	if (ty > 0)
		retprobe_map_set(e->thread_id, 1);
#endif

	/* Read out args1-5 */
	ty = config->arg0;
	if (total < MAX_TOTAL) {
		long errv;
		int a0m;

		a0m = config->arg0m;
		asm volatile("%[a0m] &= 0xffff;\n" ::[a0m] "+r"(a0m) :);

		errv = read_call_arg(ctx, e, 0, ty, total, a0, a0m, map);
		if (errv > 0)
			total += errv;
		/* Follow filter lookup failed so lets abort the event.
		 * From high-level this is a filter and should be in the
		 * filter block, but its just easier to do here so lets
		 * do it where it makes most sense.
		 */
		if (errv < 0)
			return filter_args_reject();
	}
	e->common.flags = 0;
	e->common.size = total;
	tail_call(ctx, tailcals, 1);
	return 0;
}

static inline __attribute__((always_inline)) int
generic_process_event_and_setup(struct pt_regs *ctx,
				struct bpf_map_def *heap_map,
				struct bpf_map_def *map,
				struct bpf_map_def *tailcals,
				struct bpf_map_def *config_map)
{
	struct msg_generic_kprobe *e;
	struct event_config *config;
	int zero = 0;

	/* Pid/Ktime Passed through per cpu map in process heap. */
	e = map_lookup_elem(heap_map, &zero);
	if (!e)
		return 0;

	config = map_lookup_elem(config_map, &zero);
	if (!config)
		return 0;

	if (config->syscall) {
		struct pt_regs *_ctx;
		_ctx = (struct pt_regs *)ctx->di;
		if (!_ctx)
			return 0;
		probe_read(&e->a0, sizeof(e->a0), &_ctx->di);
		probe_read(&e->a1, sizeof(e->a1), &_ctx->si);
		probe_read(&e->a2, sizeof(e->a2), &_ctx->dx);
		probe_read(&e->a3, sizeof(e->a3), &_ctx->r10);
		probe_read(&e->a4, sizeof(e->a4), &_ctx->r8);
	} else {
		e->a0 = ctx->di;
		e->a1 = ctx->si;
		e->a2 = ctx->dx;
		e->a3 = ctx->cx;
		e->a4 = ctx->r8;
	}
	e->common.op = MSG_OP_GENERIC_KPROBE;
	e->common.flags = 0;
	return generic_process_event0(ctx, heap_map, map, tailcals, config_map);
}

static inline __attribute__((always_inline)) int
generic_filter_submit(void *ctx, struct msg_generic_kprobe *e, long total)
{
	/* Post event */
	total += generic_kprobe_common_size();
	/* Code movement from clang forces us to inline bounds checks here */
	asm volatile("%[total] &= 0x7fff;\n"
		     "if %[total] < 9000 goto +1\n;"
		     "%[total] = 9000;\n"
		     :
		     : [total] "+r"(total)
		     :);
	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, e, total);
	return 0;
}

static inline __attribute__((always_inline)) int
generic_process_event1(void *ctx, struct bpf_map_def *heap_map,
		       struct bpf_map_def *map, struct bpf_map_def *tailcals,
		       struct bpf_map_def *config_map)
{
	unsigned long a0, a1, a2, a3, a4;
	struct execve_map_value *enter;
	struct msg_generic_kprobe *e;
	struct event_config *config;
	int zero = 0;
	bool walker = 0;
	long ty, total;
	__u32 ppid;

	/* Preamble to setup context */
	enter = event_find_curr(&ppid, 0, &walker);
	if (!enter)
		return 0;

	e = map_lookup_elem(heap_map, &zero);
	if (!e)
		return 0;

	config = map_lookup_elem(config_map, &zero);
	if (!config)
		return 0;

	total = e->common.size;

	a0 = e->a0;
	a1 = e->a1;
	a2 = e->a2;
	a3 = e->a3;
	a4 = e->a4;

	ty = config->arg1;
	if (total < MAX_TOTAL) {
		long errv;
		int a1m;

		a1m = config->arg1m;
		asm volatile("%[a1m] &= 0xffff;\n" ::[a1m] "+r"(a1m) :);

		errv = read_call_arg(ctx, e, 1, ty, total, a1, a1m, map);
		if (errv > 0)
			total += errv;
		if (errv < 0)
			return filter_args_reject();
	}
	e->common.size = total;
	tail_call(ctx, tailcals, 2);
	return 0;
}

static inline __attribute__((always_inline)) int
generic_process_event2(void *ctx, struct bpf_map_def *heap_map,
		       struct bpf_map_def *map, struct bpf_map_def *tailcals,
		       struct bpf_map_def *config_map)
{
	unsigned long a0, a1, a2, a3, a4;
	struct execve_map_value *enter;
	struct msg_generic_kprobe *e;
	struct event_config *config;
	int zero = 0;
	bool walker = 0;
	long ty, total;
	__u32 ppid;

	/* Preamble to setup context */
	enter = event_find_curr(&ppid, 0, &walker);
	if (!enter)
		return 0;

	e = map_lookup_elem(heap_map, &zero);
	if (!e)
		return 0;

	config = map_lookup_elem(config_map, &zero);
	if (!config)
		return 0;

	total = e->common.size;

	a0 = e->a0;
	a1 = e->a1;
	a2 = e->a2;
	a3 = e->a3;
	a4 = e->a4;

	ty = config->arg2;
	if (total < MAX_TOTAL) {
		long errv;
		int a2m;

		a2m = config->arg2m;
		asm volatile("%[a2m] &= 0xffff;\n" ::[a2m] "+r"(a2m) :);

		errv = read_call_arg(ctx, e, 2, ty, total, a2, a2m, map);
		if (errv > 0)
			total += errv;
		if (errv < 0)
			return filter_args_reject();
	}
	e->common.size = total;
	tail_call(ctx, tailcals, 3);
	return 0;
}

static inline __attribute__((always_inline)) int
generic_process_event3(void *ctx, struct bpf_map_def *heap_map,
		       struct bpf_map_def *map, struct bpf_map_def *tailcals,
		       struct bpf_map_def *config_map)
{
	unsigned long a0, a1, a2, a3, a4;
	struct execve_map_value *enter;
	struct msg_generic_kprobe *e;
	struct event_config *config;
	int zero = 0;
	bool walker = 0;
	long ty, total;
	__u32 ppid;

	/* Preamble to setup context */
	enter = event_find_curr(&ppid, 0, &walker);
	if (!enter)
		return 0;

	e = map_lookup_elem(heap_map, &zero);
	if (!e)
		return 0;

	config = map_lookup_elem(config_map, &zero);
	if (!config)
		return 0;

	total = e->common.size;

	a0 = e->a0;
	a1 = e->a1;
	a2 = e->a2;
	a3 = e->a3;
	a4 = e->a4;

	/* Arg filter and copy logic */
	ty = config->arg3;
	if (total < MAX_TOTAL) {
		long errv;
		int a3m;

		a3m = config->arg3m;
		asm volatile("%[a3m] &= 0xffff;\n" ::[a3m] "+r"(a3m) :);

		errv = read_call_arg(ctx, e, 3, ty, total, a3, a3m, map);
		if (errv > 0)
			total += errv;
		if (errv < 0)
			return filter_args_reject();
	}
	e->common.size = total;
	tail_call(ctx, tailcals, 4);
	return 0;
}

static inline __attribute__((always_inline)) int
generic_process_event4(void *ctx, struct bpf_map_def *heap_map,
		       struct bpf_map_def *map, struct bpf_map_def *tailcals,
		       struct bpf_map_def *config_map)
{
	unsigned long a0, a1, a2, a3, a4;
	struct execve_map_value *enter;
	struct msg_generic_kprobe *e;
	struct event_config *config;
	int zero = 0;
	bool walker = 0;
	long ty, total;
	__u32 ppid;

	/* Preamble to setup context */
	enter = event_find_curr(&ppid, 0, &walker);
	if (!enter)
		return 0;

	e = map_lookup_elem(heap_map, &zero);
	if (!e)
		return 0;

	config = map_lookup_elem(config_map, &zero);
	if (!config)
		return 0;

	total = e->common.size;

	a0 = e->a0;
	a1 = e->a1;
	a2 = e->a2;
	a3 = e->a3;
	a4 = e->a4;

	ty = config->arg4;
	if (total < MAX_TOTAL) {
		long errv;
		int a4m;

		a4m = config->arg4m;
		asm volatile("%[a4m] &= 0xffff;\n" ::[a4m] "+r"(a4m) :);

		errv = read_call_arg(ctx, e, 4, ty, total, a4, a4m, map);
		if (errv > 0)
			total += errv;
		if (errv < 0)
			return filter_args_reject();
	}
	e->common.size = total;
	/* Post event */
	total += generic_kprobe_common_size();
	tail_call(ctx, tailcals, 6);
	return 0;
}
