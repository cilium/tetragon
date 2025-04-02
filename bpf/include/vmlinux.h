/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

/* disable default preserve_access_index attribute */
#define BPF_NO_PRESERVE_ACCESS_INDEX

#if defined(__TARGET_ARCH_x86)
#include "vmlinux_generated_x86.h"
#elif defined(__TARGET_ARCH_arm64)
#include "vmlinux_generated_arm64.h"
#endif

/*
 * Local definitions that we use in tetragon and are no longer part
 * of vmlinux_generated.h.
 */

struct pid_link {
	struct hlist_node node;
	struct pid *pid;
};

struct audit_task_info {
	kuid_t loginuid;
};

struct task_struct___local {
	struct pid_link pids[PIDTYPE_MAX]; // old school pid refs
	struct pid *thread_pid;
	struct audit_task_info *audit; // Added audit_task for older kernels
	kuid_t loginuid;
};

/* Represent old kernfs node present in 5.4 kernels and older */
union kernfs_node_id {
	struct {
		/*
		 * blktrace will export this struct as a simplified 'struct
		 * fid' (which is a big data struction), so userspace can use
		 * it to find kernfs node. The layout must match the first two
		 * fields of 'struct fid' exactly.
		 */
		u32 ino;
		u32 generation;
	};
	u64 id;
};

// RHEL7 v3.10 exec ctx struct
struct ftrace_raw_sched_process_exec {
	struct trace_entry ent;
	s32 __data_loc_filename;
	pid_t pid;
	pid_t old_pid;
	char __data[0];
};

struct uts_namespace___rhel7 {
	unsigned int proc_inum;
};

struct ipc_namespace___rhel7 {
	unsigned int proc_inum;
};

struct mnt_namespace___rhel7 {
	unsigned int proc_inum;
};

struct net___rhel7 {
	unsigned int proc_inum;
};

#endif /* __VMLINUX_H__ */
