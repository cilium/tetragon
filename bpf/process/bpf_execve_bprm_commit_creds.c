// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Tetragon */

#include "vmlinux.h"
#include "api.h"
#include "bpf_tracing.h"

#include "common.h"
#include "process.h"

char _license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";

/*
 * Process execution is installing the new credentials and security attributes
 * related to the new exec.
 *
 * This program will check the current process credentials against the new
 * credentials that were adjusted by the capability LSM and will be applied to
 * current task part of the execve call.
 * For such case this hook must be when we are committing the new credentials
 * to the task being executed.
 *
 * It reads the linux_bprm->per_clear flags that are the personality flags to clear
 * when we are executing a privilged program. Normally we should check the
 * bprm->secureexec bit field if set to 1 or not. If bprm->secureexec is 1 then:
 * The AT_SECURE of auxv will have value of 1 which means executable should be treated
 * securely. Most commonly, 1 indicates that the process is executing a set-user-ID
 * or set-group-ID binary (so that its real and effective UIDs or GIDs differ
 * from one another), or that it gained capabilities by executing a binary file
 * that has capabilities (see capabilities(7)).
 * Alternatively, a nonzero value may be triggered by a Linux Security Module.
 * When this value is nonzero, the dynamic linker disables the use of certain
 * environment variables.
 *
 * However since bprm->secreexec is a bit field we have to assume and compute its
 * offset to locate it first. An alternative way is to check the brpm->per_clear
 * personality flags that will also be set if it is a privileged execution.
 *
 * After that we check the credential fields and guess which privileged execution.
 * Example: if linux_bprm->cred->{euid,egid} differ from current uid and gid
 * then this is probably a set-user-id or set-group-id execution.
 */
__attribute__((section("kprobe/security_bprm_committing_creds"), used)) void
BPF_KPROBE(tg_kp_bprm_committing_creds, struct linux_binprm *bprm)
{
	struct execve_map_value *curr;
	struct execve_heap *heap;
	struct task_struct *task;
	__u32 pid, euid, uid, egid, gid, sec = 0, zero = 0;
	__u64 tid;

	sec = BPF_CORE_READ(bprm, per_clear);
	/* If no flags to clear then this is not a privileged execution */
	if (!sec)
		return;

	tid = get_current_pid_tgid();
	pid = (tid >> 32);

	curr = execve_map_get_noinit(pid);
	if (!curr)
		return;

	heap = map_lookup_elem(&execve_heap, &zero);
	if (!heap)
		return;

	memset(&heap->info, 0, sizeof(struct execve_info));

	/* Check if this is a setuid or setgid */
	euid = BPF_CORE_READ(bprm, cred, euid.val);
	egid = BPF_CORE_READ(bprm, cred, egid.val);

	task = (struct task_struct *)get_current_task();
	uid = BPF_CORE_READ(task, cred, uid.val);
	gid = BPF_CORE_READ(task, cred, gid.val);

	/* Is setuid? */
	if (euid != uid)
		heap->info.secureexec |= EXEC_SETUID;
	/* Is setgid? */
	if (egid != gid)
		heap->info.secureexec |= EXEC_SETGID;

	/* Do we cache the entry? */
	if (heap->info.secureexec != 0)
		execve_joined_info_map_set(tid, &heap->info);
}
