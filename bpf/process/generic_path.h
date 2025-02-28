// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __GENERIC_PATH_H__
#define __GENERIC_PATH_H__

#include "bpf_d_path.h"
#include "compiler.h"

enum {
	STATE_INIT,
	STATE_WORK,
};

#ifndef __V61_BPF_PROG

FUNC_INLINE int get_off(char *buffer, char *buf)
{
	return buf - buffer;
}

FUNC_INLINE char *get_buf(char *buffer, int off)
{
	asm volatile("%[off] &= 0xfff;\n" : [off] "+r"(off));
	return buffer + off;
}

FUNC_INLINE long path_init(void *ctx, struct generic_path *gp, struct bpf_map_def *tailcals)
{
	const struct path *path = gp->path;
	struct task_struct *task;
	const struct path *root;
	struct dentry *dentry;
	struct fs_struct *fs;
	char *buffer, *buf;
	int zero = 0, buflen = MAX_BUF_LEN;

	buffer = map_lookup_elem(&buffer_heap_map, &zero);
	if (!buffer)
		return 0;

	buf = buffer + MAX_BUF_LEN - 1;
	probe_read(&dentry, sizeof(dentry), _(&path->dentry));
	if (d_unlinked(dentry)) {
		// prepend will never return a value != 0
		prepend(&buf, &buflen, " (deleted)", 10);
	}

	task = (struct task_struct *)get_current_task();
	probe_read(&fs, sizeof(fs), _(&task->fs));

	root = _(&fs->root);
	path = gp->path;

	probe_read(&gp->root_dentry, sizeof(gp->root_dentry), _(&root->dentry));
	probe_read(&gp->root_mnt, sizeof(gp->root_mnt), _(&root->mnt));
	probe_read(&gp->dentry, sizeof(gp->dentry), _(&path->dentry));
	probe_read(&gp->vfsmnt, sizeof(gp->vfsmnt), _(&path->mnt));
	gp->mnt = real_mount(gp->vfsmnt);

	gp->cnt = 0;
	gp->off = get_off(buffer, buf);
	gp->state = STATE_WORK;
	tail_call(ctx, tailcals, TAIL_CALL_PATH);
	return 0;
}

#define GENERIC_PATH_CALLS 8

#ifdef __LARGE_BPF_PROG
#define GENERIC_PATH_ITERATIONS 512
#else
#define GENERIC_PATH_ITERATIONS 32
#endif

FUNC_INLINE long path_work(void *ctx, struct generic_path *gp, struct bpf_map_def *tailcals)
{
	struct cwd_read_data data = {
		.root_dentry = gp->root_dentry,
		.root_mnt = gp->root_mnt,
		.dentry = gp->dentry,
		.vfsmnt = gp->vfsmnt,
		.mnt = gp->mnt,
	};
	char *buffer;
	int zero = 0;

	buffer = map_lookup_elem(&buffer_heap_map, &zero);
	if (!buffer)
		return 0;

	data.bf = buffer;
	data.bptr = get_buf(buffer, gp->off);
	data.blen = gp->off;

#pragma unroll
	for (int i = 0; i < GENERIC_PATH_ITERATIONS; ++i) {
		if (cwd_read(&data))
			break;
	}

	gp->cnt++;
	gp->off = get_off(buffer, data.bptr);

	if (data.resolved || gp->cnt == GENERIC_PATH_CALLS) {
		tail_call(ctx, tailcals, TAIL_CALL_PROCESS);
		return 0;
	}

	gp->dentry = data.dentry;
	gp->vfsmnt = data.vfsmnt;
	gp->mnt = data.mnt;

	tail_call(ctx, tailcals, TAIL_CALL_PATH);
	return 0;
}

FUNC_INLINE long generic_path(void *ctx, struct bpf_map_def *tailcals)
{
	struct msg_generic_kprobe *e;
	int zero = 0;

	e = map_lookup_elem(&process_call_heap, &zero);
	if (!e)
		return 0;

	switch (e->path.state) {
	case STATE_INIT:
		return path_init(ctx, &e->path, tailcals);
	case STATE_WORK:
		return path_work(ctx, &e->path, tailcals);
	}

	return 0;
}

FUNC_INLINE void generic_path_init(struct msg_generic_kprobe *e)
{
	e->path.state = STATE_INIT;
}

/*
 * The path offload is plugged in roughly as follows:
 *
 * TAIL_CALL_PROCESS:               <-----.
 *   generic_process_event                |
 *     generic_path_offload               |
 *       if type is path                  |
 *         tail_call TAIL_CALL_PATH -.    |
 *       if path is resolved         |    |
 *         store_path                |    |
 *                                   |    |
 * TAIL_CALL_PATH:          <--------'    |
 *   generic_path                         |
 *     path_init                          |
 *       tail_call TAIL_CALL_PATH -----.  |
 *                                     |  |
 * TAIL_CALL_PATH:          <------.<--'  |
 *   generic_path                  |      |
 *     path_work                   |      |
 *       read directory entry      |      |
 *       tail_call TAIL_CALL_PATH -'      |
 *                                        |
 *       if final entry                   |
 *         tail_call TAIL_CALL_PROCESS ---'
 */
FUNC_INLINE long generic_path_offload(void *ctx, long ty, unsigned long arg,
				      int index, unsigned long orig_off,
				      struct bpf_map_def *tailcals)
{
	struct msg_generic_kprobe *e;
	struct generic_path *gp;
	const struct path *path;
	char *args, *buffer, *buf;
	int zero = 0;

	e = map_lookup_elem(&process_call_heap, &zero);
	if (!e)
		return 0;

	gp = &e->path;
	if (gp->state == STATE_INIT) {
		path = get_path(ty, arg, &gp->path_buf);
		if (!path)
			return 0;
		gp->path = path;
		tail_call(ctx, tailcals, TAIL_CALL_PATH);
		return 0;
	}

	/* initialize for next argument */
	generic_path_init(e);

	buffer = map_lookup_elem(&buffer_heap_map, &zero);
	if (!buffer)
		return 0;

	e->argsoff[index & MAX_SELECTORS_MASK] = orig_off;
	args = args_off(e, orig_off);
	buf = get_buf(buffer, gp->off);
	return store_path(args, buf, gp->path, MAX_BUF_LEN - gp->off - 1, 0);
}

FUNC_INLINE bool should_offload_path(long type)
{
	switch (type) {
	case kiocb_type:
	case file_ty:
	case path_ty:
	case dentry_type:
	case linux_binprm_type:
		return true;
	}
	return false;
}
#else
FUNC_INLINE void generic_path_init(struct msg_generic_kprobe *e) {}

FUNC_INLINE long generic_path_offload(void *ctx, long ty, unsigned long arg,
				      int index, unsigned long orig_off,
				      struct bpf_map_def *tailcals)
{
	return 0;
}

FUNC_INLINE bool should_offload_path(long ty)
{
	return false;
}
#endif /* !__V61_BPF_PROG */

#endif /* __GENERIC_PATH_H__ */
