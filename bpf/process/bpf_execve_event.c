// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#include "vmlinux.h"
#include "api.h"

#include "hubble_msg.h"
#include "bpf_events.h"
#include "bpf_process_event.h"
#include "bpf_helpers.h"

char _license[] __attribute__((section("license"), used)) = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} execve_calls SEC(".maps");

#ifdef __LARGE_BPF_PROG
#include "data_event.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct msg_data);
} data_heap SEC(".maps");
#endif

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct inode);
} inode_heap SEC(".maps");

struct exec_policy_key {
	__u8 cookie[64];
};

struct exec_policy_value {
	__u8 parent[64];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct exec_policy_key);
	__type(value, struct exec_policy_value);
} execve_allow_policy SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, __u32);
} execve_cgroup_enabled SEC(".maps");

/* event_args_builder: copies args into char *buffer
 * event: pointer to event storage
 * pargs: kernel address of args structure
 *
 * returns: void, because we are using asm_goto here we can't easily
 * also provide return values. To avoid having to try and introspect
 * what happened here this routine should always return with a good
 * event msg that could be passed to userspace.
 */
static inline __attribute__((always_inline)) void
event_args_builder(void *ctx, struct msg_execve_event *event)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	struct msg_process *p, *c;
	struct mm_struct *mm;

	/* Calculate absolute offset into buffer */
	c = &event->process;
	c->auid = get_auid();
	p = c;

	/* We use flags in asm to indicate overflow */
	compiler_barrier();
	probe_read(&mm, sizeof(mm), _(&task->mm));
	if (mm) {
		unsigned long start_stack, end_stack;
		struct execve_heap *heap;
		__u32 zero = 0;
		long off;

		probe_read(&start_stack, sizeof(start_stack),
			   _(&mm->arg_start));
		probe_read(&end_stack, sizeof(start_stack), _(&mm->arg_end));

		if (!start_stack || !end_stack)
			return;

		/* skip first argument - binary path */
		heap = map_lookup_elem(&execve_heap, &zero);
		if (!heap)
			return;

		/* poor man's strlen */
		off = probe_read_str(&heap->maxpath, 4096, (char *)start_stack);
		if (off < 0)
			return;

		start_stack += off;

#ifndef __LARGE_BPF_PROG
		probe_arg_read(c, (char *)p, (char *)start_stack,
			       (char *)end_stack);
#else
		if ((end_stack - start_stack) < BUFFER) {
			probe_arg_read(c, (char *)p, (char *)start_stack,
				       (char *)end_stack);
		} else {
			char *args = (char *)p + p->size;
			__u32 size;

			if (args >= (char *)&event->process + BUFFER)
				return;

			size = data_event_bytes(
				ctx, (struct data_event_desc *)args,
				(unsigned long)start_stack,
				end_stack - start_stack,
				(struct bpf_map_def *)&data_heap);
			if (size < 0)
				return;
			p->size += size;
			p->flags |= EVENT_DATA_ARGS;
		}
#endif
	}
}

#define MAX_DIGEST_SIZE 64
#define DIGEST_SHA256 32

static inline __attribute__((always_inline)) int
event_digest_policy(struct msg_process *curr)
{
	struct exec_policy_value *allowed;
	int i;

	// enable gate on cgroup id

	// ah check i_flag through IS_VERITY
	for (i = 0; i < DIGEST_SHA256; i++) {
		if (curr->digest[0] != 0)
			break;
	}
	if (i == 32)
		return 0;

	allowed = map_lookup_elem(&execve_allow_policy, &curr->digest);
	if (!allowed) {
		for (i = 0; i < DIGEST_SHA256; i++)
			bpf_printk("%d: %d\n", i, curr->digest[i]);
		//send_signal(9);
		return 1;
	}
	return 0;
}

static inline __attribute__((always_inline)) void
event_inode_builder(void *ctx,  struct linux_binprm *bprm, struct msg_process *curr)
{
	struct inode *f_inode;
	struct file *file;
	struct fsverity_info *i_verity_info;
	int is_ovl = 1;
	struct path f_path;
	struct dentry *dentry;
	struct ovl_entry *oentry;
	unsigned numlower;
	struct ovl_path lower;

	probe_read(&file, sizeof(file), _(&bprm->file));
	probe_read(&f_inode, sizeof(f_inode), _(&file->f_inode));
	probe_read(&f_path, sizeof(struct path), _(&file->f_path));
	probe_read(&dentry, sizeof(dentry), _(&f_path.dentry));
	probe_read(&oentry, sizeof(oentry), _(&dentry->d_fsdata));
	if (!oentry)
		return;
	probe_read(&numlower, sizeof(numlower), &oentry->numlower);
	probe_read(&lower, sizeof(lower), &oentry->lowerstack[0]);
	probe_read(&dentry, sizeof(dentry), &lower.dentry);

	probe_read(&f_inode, sizeof(f_inode), _(&dentry->d_inode));

	bpf_printk("entry num lower %d\n", numlower);
	if (is_ovl) {
		struct ovl_inode *ovl;
		__u64 offset = offsetof(struct ovl_inode, vfs_inode);
		__u64 version, flags;
		struct inode *orig_node;
		struct inode *ovll;
		int zero = 0;

		orig_node = map_lookup_elem(&inode_heap, &zero);
		if (!orig_node)
			return;

#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})

		ovl = container_of(f_inode, struct ovl_inode, vfs_inode);
		//ovl = (struct ovl_inode *)((char *)f_inode - offset);
		//bpf_printk("inode %p - %d = %p\n", (long) f_inode, offset,
				//(long)f_inode - offset);
//		if (ovl != 0) {
//			void *addr = &ovl->lowerdata;

		bpf_printk("original f_inode %p\n", f_inode);
		probe_read(&ovll, sizeof(struct dentry *), &ovl->lower);
	//	probe_read(&f_inode, sizeof(f_inode), &ovl->lowerdata);
		probe_read(orig_node, sizeof(struct inode), ovll);
		bpf_printk("f_inode %p ovl %p offset %d\n", f_inode, ovl, offset);
		probe_read(&version, sizeof(version), &ovl->version);
		probe_read(&flags, sizeof(flags), &ovl->flags);
		bpf_printk("version %d flags %d ovl %p\n", version, flags, ovl);
		bpf_printk("ovll %p origi i_no %u\n", ovll, orig_node->i_ino);

	}

	probe_read(&curr->i_ino, sizeof(curr->i_ino), _(&f_inode->i_ino));

	probe_read(&i_verity_info, sizeof(i_verity_info), _(&f_inode->i_verity_info));
	probe_read(&curr->digest, MAX_DIGEST_SIZE, _(&i_verity_info->file_digest));
	bpf_printk("curr->digest %p %x %x\n", i_verity_info, curr->digest[1], curr->digest[2]);
	bpf_printk("i_node %u\n", curr->i_ino);
}

static inline __attribute__((always_inline)) uint32_t
event_filename_builder(void *ctx, struct msg_process *curr, __u32 curr_pid,
		       __u32 flags, __u32 bin, void *filename)
{
	struct execve_heap *heap;
	int64_t size = 0;
	__u32 zero = 0;
	uint32_t *value;
	char *earg;

	/* This is a bit parnoid but was previously having trouble on
	 * 4.14 kernels tracking offset of curr through filename_builder
	 * resulting in a a verifier error. We can optimize this a bit
	 * later perhaps and push as an argument.
	 */
	earg = (void *)curr + offsetof(struct msg_process, args);

	size = probe_read_str(earg, MAXARGLENGTH - 1, filename);
	if (size < 0) {
		flags |= EVENT_ERROR_FILENAME;
		size = 0;
	} else if (size == MAXARGLENGTH - 1) {
#ifndef __LARGE_BPF_PROG
		flags |= EVENT_TRUNC_FILENAME;
#else
		size = data_event_str(ctx, (struct data_event_desc *)earg,
				      (unsigned long)filename,
				      (struct bpf_map_def *)&data_heap);
		if (size < 0) {
			flags |= EVENT_ERROR_FILENAME;
			size = 0;
		} else {
			flags |= EVENT_DATA_FILENAME;
		}
#endif
	}
	curr->flags = flags;
	curr->pid = curr_pid;
	curr->nspid = get_task_pid_vnr();
	curr->ktime = ktime_get_ns();
	curr->size = size + offsetof(struct msg_process, args);

	heap = map_lookup_elem(&execve_heap, &zero);
	if (!heap)
		return bin;

	probe_read_str(heap->pathname, 255, filename);
	value = map_lookup_elem(&names_map, heap->pathname);
	if (value)
		return *value;
	return bin;
}

__attribute__((section("raw_tracepoint/sys_execve"), used)) int
event_execve(struct bpf_raw_tracepoint_args *ctx)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	struct linux_binprm *bprm = (struct linux_binprm *)ctx->args[2];
	struct msg_execve_event *event;
	struct execve_map_value *parent;
	struct msg_process *execve;
	uint32_t binary = 0;
	bool walker = 0;
	__u32 zero = 0;
	char *filename;
	__u32 pid;

	event = map_lookup_elem(&execve_msg_heap_map, &zero);
	if (!event)
		return 0;
	pid = (get_current_pid_tgid() >> 32);
	parent = event_find_parent();
	if (parent) {
		event->parent = parent->key;
		binary = parent->binary;
	} else {
		event_minimal_parent(event, task);
	}

	execve = &event->process;
	event_inode_builder(ctx, bprm, execve);
	probe_read(&filename, sizeof(filename), _(&bprm->filename));
	binary = event_filename_builder(ctx, execve, pid, EVENT_EXECVE, binary, filename);
	event->binary = binary;

	event_args_builder(ctx, event);
	compiler_barrier();
	__event_get_task_info(event, MSG_OP_EXECVE, walker, true);

	tail_call(ctx, &execve_calls, 0);
	return 0;
}

__attribute__((section("raw_tracepoint/0"), used)) int
execve_send(void *ctx)
{
	struct msg_execve_event *event;
	struct execve_map_value *curr;
	struct msg_process *execve;
	__u32 zero = 0;
	uint64_t size;
	int verdict;
	__u32 pid;
#if defined(__NS_CHANGES_FILTER) || defined(__CAP_CHANGES_FILTER)
	bool init_curr = 0;
#endif


	event = map_lookup_elem(&execve_msg_heap_map, &zero);
	if (!event)
		return 0;

	execve = &event->process;

	pid = (get_current_pid_tgid() >> 32);

	curr = execve_map_get(pid);
	if (curr) {
		event->cleanup_key = curr->key;
#if defined(__NS_CHANGES_FILTER) || defined(__CAP_CHANGES_FILTER)
		/* if this exec event preceds a clone, initialize  capabilities
		 * and namespaces as well.
		 */
		if (curr->flags == EVENT_COMMON_FLAG_CLONE)
			init_curr = 1;
#endif
		curr->key.pid = execve->pid;
		curr->key.ktime = execve->ktime;
		curr->nspid = execve->nspid;
		curr->pkey = event->parent;
		if (curr->flags & EVENT_COMMON_FLAG_CLONE) {
			event_set_clone(execve);
		}
		curr->flags = 0;
		curr->binary = event->binary;
#ifdef __NS_CHANGES_FILTER
		if (init_curr)
			memcpy(&(curr->ns), &(event->ns),
			       sizeof(struct msg_ns));
#endif
#ifdef __CAP_CHANGES_FILTER
		if (init_curr) {
			curr->caps.permitted = event->caps.permitted;
			curr->caps.effective = event->caps.effective;
			curr->caps.inheritable = event->caps.inheritable;
		}
#endif
	}

	verdict = event_digest_policy(execve);
	bpf_printk("verdict %d\n", verdict);

	event->common.flags = 0;
	size = validate_msg_execve_size(
		sizeof(struct msg_common) + sizeof(struct msg_k8s) +
		sizeof(struct msg_execve_key) + sizeof(__u64)  +
		sizeof(struct msg_capabilities) + sizeof(struct msg_ns) +
		sizeof(struct msg_execve_key) + execve->size);
	perf_event_output(ctx, &tcpmon_map, BPF_F_CURRENT_CPU, event, size);
	return 0;
}
