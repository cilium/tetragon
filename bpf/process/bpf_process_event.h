// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Cilium */

#ifndef _BPF_PROCESS_EVENT__
#define _BPF_PROCESS_EVENT__

#define ENAMETOOLONG  36 /* File name too long */
#define PATH_MAP_SIZE 4096

struct bpf_map_def __attribute__((section("maps"), used)) buffer_heap_map = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(int),
	.value_size = PATH_MAP_SIZE * sizeof(char),
	.max_entries = 1,
};

static inline __attribute__((always_inline)) __u64
__get_auid(struct task_struct *task)
{
	// u64 to convince compiler to do 64bit loads early kernels do not
	// support 32bit loads from stack, e.g. r1 = *(u32 *)(r10 -8).
	__u64 auid = 0;

	if (!task)
		return auid;

	if (bpf_core_field_exists(task->loginuid)) {
		probe_read(&auid, sizeof(auid), _(&task->loginuid.val));
	} else {
		struct audit_task_info *audit;

		if (bpf_core_field_exists(task->audit)) {
			probe_read(&audit, sizeof(audit), _(&task->audit));
			if (audit) {
				probe_read(&auid, sizeof(__u32),
					   _(&audit->loginuid));
			}
		}
	}

	return auid;
}

static inline __attribute__((always_inline)) __u32 get_auid(void)
{
	struct task_struct *task = (struct task_struct *)get_current_task();

	return __get_auid(task);
}

static inline __attribute__((always_inline)) __u64
get_parent_auid(struct task_struct *t)
{
	struct task_struct *task = get_parent(t);

	return __get_auid(task);
}

#define CWD_DENTRY_REG	      "r9"
#define CWD_VFSMNT_DENTRY_REG "r6"
#define CWD_OFFSET_REG	      "r7"

#define PROBE_CWD_READ_LOOP_HEADER                                             \
	CWD_DENTRY_REG " = *(u64 *)%[dentry];\n" CWD_VFSMNT_DENTRY_REG         \
		       " = *(u64 *)%[vfsmnt];\n" CWD_OFFSET_REG                \
		       " = *(u32 *)%[offset];\n"

#define PROBE_CWD_READ                                                                           \
	/* if (!dentry) { break; } */                                                            \
	"r3 = " CWD_DENTRY_REG ";\n"                                                             \
	"if r3 == 0 goto %l[a];\n" /* probe_read(&parent, sizeof(parent), &dentry->d_parent); */ \
	"r2 = *(u32 *)%[dentry_parent];\n"                                                       \
	"r3 += r2;\n"                                                                            \
	"r2 = 8;\n"                                                                              \
	"r1 = %[ptr];\n"                                                                         \
	"call 4;\n" /* if (!parent) { break; } */                                                \
	"r4 = *(u64 *)(%[ptr] + 0);\n"                                                           \
	"if r4 == 0x0 goto %l[a];\n" /* if (vfsmnt_dentry && dentry == vfsmnt_dentry) { */       \
	"if " CWD_VFSMNT_DENTRY_REG " == " CWD_DENTRY_REG                                        \
	" goto %l[a];\n" /* if (dentry == dentry->d_parent) { */                                 \
	"if r4 == " CWD_DENTRY_REG                                                               \
	" goto %l[a];\n" /* name = &dentry->d_name; */                                           \
	/* dentry = parent; */ /* probe_read(&dname, sizeof(dname), &name->name); */             \
	"r3 = " CWD_DENTRY_REG ";\n"                                                             \
	"r2 = *(u32 *)%[dentry_name];\n"                                                         \
	"r3 += r2;\n" CWD_DENTRY_REG " = r4;\n" /* r9 = parent */                                \
	"r1 = %[ptr];\n"                                                                         \
	"r2 = 8;\n"                                                                              \
	"call 4;\n" /* pcwd = curr + offset */ /* probe_read(pcwd, 1, &slash); */                \
	"r1 = *(u64 *)%[pid];\n" CWD_OFFSET_REG " &= 0x3FF;\n"                                   \
	"r1 += " CWD_OFFSET_REG ";\n"                                                            \
	"r2 = 1;\n"                                                                              \
	"r3 = *(u64 *)%[slash];\n"                                                               \
	"call 4;\n" /* pcwd++; */ /* ret = probe_read_str(pcwd, CWD_MAX, dname); */              \
		CWD_OFFSET_REG " += 1;\n"                                                        \
	"r1 = *(u64 *)%[pid];\n" CWD_OFFSET_REG " &= 0x3FF;\n"                                   \
	"r1 += " CWD_OFFSET_REG ";\n"                                                            \
	"r2 = " XSTR(                                                                            \
		CWD_MAX) ";\n"                                                                   \
			 "r3 = *(u64 *)(%[ptr] + 0);\n"                                          \
			 "call 45;\n" /* if (ret < 0) { */ /* cwdsize += ret */                  \
			 "if r0 s< 1 goto %l[a];\n"                                              \
			 "r0 -= 1\n;" CWD_OFFSET_REG " += r0;\n"                                 \
			 "*(u32 *)%[offset] = " CWD_OFFSET_REG                                   \
			 ";\n" /* count iterations */                                            \
			 "r3 = *(u32 *)%[iter];\n"                                               \
			 "r3 += 1;\n"                                                            \
			 "*(u32 *)%[iter] = r3;\n"

/* we cannot avoid probe_read calls here as
 * something line "*(u8 *)(r1 + 0) = r3;\n"
 * fails.
 */
#define MARK_PATH_WITH_SYMBOLS                                                 \
	"r1 = *(u64 *)%[pid];\n" CWD_OFFSET_REG " &= 0x3FF;\n"                 \
	"r1 += " CWD_OFFSET_REG ";\n"                                          \
	"r2 = 1;\n"                                                            \
	"r3 = *(u64 *)%[slash];\n"                                             \
	"call 4;\n" CWD_OFFSET_REG " += 1;\n"                                  \
	"r1 = *(u64 *)%[pid];\n" CWD_OFFSET_REG " &= 0x3FF;\n"                 \
	"r1 += " CWD_OFFSET_REG ";\n"                                          \
	"r2 = 1;\n"                                                            \
	"r3 = *(u64 *)%[symbol];\n"                                            \
	"call 4;\n" CWD_OFFSET_REG " += 1;\n"

#define MARK_UNRESOLVED_PATH_IF_NEEDED                                             \
	"if r3 < " XSTR(                                                           \
		PROBE_CWD_READ_ITERATIONS) " goto %l[a];\n" MARK_PATH_WITH_SYMBOLS \
					   "*(u32 *)%[offset] = " CWD_OFFSET_REG   \
					   ";\n"

#define offsetof_btf(s, memb) ((size_t)((char *)_(&((s *)0)->memb) - (char *)0))

#define container_of_btf(ptr, type, member)                                    \
	({                                                                     \
		void *__mptr = (void *)(ptr);                                  \
		((type *)(__mptr - offsetof_btf(type, member)));               \
	})

static inline __attribute__((always_inline)) u32
getpath(void *curr, struct dentry *dentry, struct vfsmount *vfsmnt,
	volatile u32 offset, u32 *flags)
{
	long dentry_parent, dentry_name;
	char slash = '/', *pslash = &slash;
	char symbol = '&', *psymbol = &symbol;
	long *ptr = 0;
	struct dentry *vfsmnt_dentry = 0;
	u32 iter = 0;

	/* Verify complains if this is not a constant (compiler optimizes
	 * us into a corner ottherwise). So for now note qstr->name is 8
	 * bytes into struct on all kernels we use.
	 */
	const int qstr = 8;

	if (vfsmnt)
		probe_read(&vfsmnt_dentry, sizeof(vfsmnt_dentry),
			   _(&vfsmnt->mnt_root));

	dentry_parent = offsetof_btf(struct dentry, d_parent);
	dentry_name = offsetof_btf(struct dentry, d_name);
	dentry_name += qstr;

	/* For 'asm goto' offset needs to be a memory address otherwise
	 * code may load the value from memory into a register in the preheader,
	 * but then goto logic will not know to load final result back into
	 * memory on goto exit. The result is some code like this,
	 *
	 * call 45
	 * if r0 s< 1 goto +42 <LBB0_77>
	 * r0 -= 1
	 * r7 += r0
	 * *(u64 *)(r10 - 168) = r7
	 *
	 * Notice we skip the load at the end needed to push offset back into
	 * stack. Later we might have code like this,
	 *
	 * r3 = *(u64 *)(r10 - 168)
	 *
	 * That expect to load the new offset, but its not there. To make
	 * things extra convoluted we are short on registers so can't mark
	 * offset as clobbered. In order to defeat compiler though we mark
	 * offset volatile above and this forces the retrun __offset to reload
	 * the value from stack.
	 */
	asm volatile goto(
		PROBE_CWD_READ_LOOP_HEADER M_REPEAT(PROBE_CWD_READ_ITERATIONS,
						    PROBE_CWD_READ)
			MARK_UNRESOLVED_PATH_IF_NEEDED
		:
		: [pid] "m"(curr), [vfsmnt] "m"(vfsmnt_dentry),
		  [dentry] "m"(dentry), [ptr] "+r"(&ptr), [slash] "m"(pslash),
		  [symbol] "m"(psymbol), [dentry_parent] "m"(dentry_parent),
		  [dentry_name] "m"(dentry_name), [offset] "+m"(offset),
		  [iter] "+m"(iter)
		: "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r9", "memory"
		: a);
a:
	if (iter >= PROBE_CWD_READ_ITERATIONS)
		*flags |= UNRESOLVED_PATH_COMPONENTS;
	return offset;
}

static inline __attribute__((always_inline)) u32
mark_unresolved(void *curr, struct mount *mnt)
{
	struct mount *local_mnt;
	struct dentry *dentry, *dentry_parent;

	probe_read(&local_mnt, sizeof(struct mount *), _(&(mnt->mnt_parent)));
	probe_read(&dentry, sizeof(struct dentry *),
		   _(&(local_mnt->mnt_mountpoint)));
	probe_read(&dentry_parent, sizeof(struct dentry *),
		   _(&(dentry->d_parent)));

	if (dentry == dentry_parent) // IS_ROOT(dentry)
		return 0;
	return 1;
}

static inline __attribute__((always_inline)) struct mount *
real_mount(struct vfsmount *mnt)
{
	return container_of_btf(mnt, struct mount, mnt);
}

static inline __attribute__((always_inline)) struct mount *
follow_mount_point(struct mount *mnt, void *argp, u32 *size, u32 *flags)
{
	struct dentry *dentry, *dentry_parent;
	struct mount *local_mnt;

	if (!mnt)
		return 0;

	probe_read(&local_mnt, sizeof(struct mount *), _(&(mnt->mnt_parent)));
	probe_read(&dentry, sizeof(struct dentry *),
		   _(&(local_mnt->mnt_mountpoint)));
	*size = getpath(argp, dentry, 0, *size, flags);

	probe_read(&dentry_parent, sizeof(struct dentry *),
		   _(&(dentry->d_parent)));
	if (dentry == dentry_parent) /* IS_ROOT(dentry) */
		return 0;

	return local_mnt;
}

static inline __attribute__((always_inline)) u32
get_full_path(struct path *path, void *argp, u32 offset, u32 *flags)
{
	struct path pwd;
	struct mount *mnt;
	struct dentry *dentry, *dentry_parent;
	u32 mnt_unresolved = 0;
#ifdef __LARGE_BPF_PROG
	int i = 0;
#endif

	probe_read(&pwd, sizeof(pwd), path);
	offset = getpath(argp, pwd.dentry, pwd.mnt, offset, flags);

	/* get first mount point through mnt->mnt_mountpoint */
	mnt = real_mount(pwd.mnt);
	probe_read(&dentry, sizeof(struct dentry *), _(&(mnt->mnt_mountpoint)));
	offset = getpath(argp, dentry, 0, offset, flags);

	probe_read(&dentry_parent, sizeof(struct dentry *),
		   _(&(dentry->d_parent)));
	if (dentry != dentry_parent) { // !IS_ROOT(dentry)
#ifdef __LARGE_BPF_PROG
		for (i = 0; i < MAX_MOUNT_POINTS; ++i)
			if ((mnt = follow_mount_point(mnt, argp, &offset,
						      flags)) == 0)
				break;
#else
		// one more call to support at max 2 mount points
		mnt = follow_mount_point(mnt, argp, &offset, flags);
#endif
		mnt_unresolved = mark_unresolved(argp, mnt);
	}

	if (mnt_unresolved)
		*flags |= UNRESOLVED_MOUNT_POINTS;

	return offset;
}

static inline __attribute__((always_inline)) bool IS_ROOT(struct dentry *dentry)
{
	struct dentry *d_parent;

	probe_read(&d_parent, sizeof(d_parent), _(&dentry->d_parent));
	return (dentry == d_parent);
}

static inline __attribute__((always_inline)) bool
hlist_bl_unhashed(const struct hlist_bl_node *h)
{
	struct hlist_bl_node **pprev;

	probe_read(&pprev, sizeof(pprev), _(&h->pprev));
	return !pprev;
}

static inline __attribute__((always_inline)) int
d_unhashed(struct dentry *dentry)
{
	return hlist_bl_unhashed(_(&dentry->d_hash));
}

static inline __attribute__((always_inline)) int
d_unlinked(struct dentry *dentry)
{
	return d_unhashed(dentry) && !IS_ROOT(dentry);
}

static inline __attribute__((always_inline)) int
prepend_name(char *bf, char **buffer, int *buflen, const char *name, u32 dlen)
{
	char slash = '/';
	u64 buffer_offset;

	if (buffer == 0)
		return -ENAMETOOLONG;

	buffer_offset = (u64)(*buffer) - (u64)bf;

	*buflen -= (dlen + 1);
	if (*buflen < 0)
		return -ENAMETOOLONG;

	buffer_offset -= (dlen + 1);

	if (dlen > 255)
		return -ENAMETOOLONG;
	if (buffer_offset > PATH_MAP_SIZE - 256)
		return -ENAMETOOLONG;

	probe_read(bf + buffer_offset, sizeof(char), &slash);
	asm volatile("%[dlen] &= 0xff;\n" ::[dlen] "+r"(dlen) :);
	probe_read(bf + buffer_offset + 1, dlen * sizeof(char), name);

	*buffer = bf + buffer_offset;
	return 0;
}

static inline __attribute__((always_inline)) int
prepend(char **buffer, int *buflen, const char *str, int namelen)
{
	*buflen -= namelen;
	if (*buflen < 0)
		return -ENAMETOOLONG;
	*buffer -= namelen;
	memcpy(*buffer, str, namelen);
	return 0;
}

static inline __attribute__((always_inline)) int
prepend_path(const struct path *path, const struct path *root, char *bf,
	     char **buffer, int *buflen)
{
	struct dentry *dentry;
	struct vfsmount *vfsmnt;
	struct mount *mnt;
	struct qstr d_name;
	int error = 0;
	char *bptr;
	int i, blen;
	bool resolved = false;

	bptr = *buffer;
	blen = *buflen;
	probe_read(&dentry, sizeof(dentry), _(&path->dentry));
	probe_read(&vfsmnt, sizeof(vfsmnt), _(&path->mnt));
	mnt = real_mount(vfsmnt);

#ifndef __LARGE_BPF_PROG
#pragma unroll
#endif
	for (i = 0; i < PROBE_CWD_READ_ITERATIONS; ++i) {
		struct dentry *parent;
		struct dentry *vfsmnt_mnt_root;
		struct vfsmount *root_mnt;
		struct dentry *root_dentry;

		probe_read(&root_dentry, sizeof(root_dentry), _(&root->dentry));
		probe_read(&root_mnt, sizeof(root_mnt), _(&root->mnt));
		if (!(dentry != root_dentry || vfsmnt != root_mnt)) {
			resolved = true;
			break;
		}

		probe_read(&vfsmnt_mnt_root, sizeof(vfsmnt_mnt_root),
			   _(&vfsmnt->mnt_root));
		if (dentry == vfsmnt_mnt_root || IS_ROOT(dentry)) {
			struct mount *parent;

			probe_read(&parent, sizeof(parent),
				   _(&mnt->mnt_parent));

			/* Global root? */
			if (mnt != parent) {
				probe_read(&dentry, sizeof(dentry),
					   _(&mnt->mnt_mountpoint));
				mnt = parent;
				probe_read(&vfsmnt, sizeof(vfsmnt),
					   _(&mnt->mnt));
				continue;
			}

			resolved = true;
			break;
		}
		probe_read(&parent, sizeof(parent), _(&dentry->d_parent));
		probe_read(&d_name, sizeof(d_name), _(&dentry->d_name));
		error = prepend_name(bf, &bptr, &blen,
				     (const char *)d_name.name, d_name.len);
		if (error)
			break;

		dentry = parent;
	}
	if (bptr == *buffer) {
		*buflen = 0;
		return 0;
	}
	if (!resolved)
		error = UNRESOLVED_PATH_COMPONENTS;
	*buffer = bptr;
	*buflen = blen;
	return error;
}

static inline __attribute__((always_inline)) int
path_with_deleted(const struct path *path, const struct path *root, char *bf,
		  char **buf, int *buflen)
{
	struct dentry *dentry;

	probe_read(&dentry, sizeof(dentry), _(&path->dentry));
	if (d_unlinked(dentry)) {
		int error = prepend(buf, buflen, " (deleted)", 10);

		if (error)
			return error;
	}
	return prepend_path(path, root, bf, buf, buflen);
}

/* the 'buf' argument should be always the value of 'buffer_heap_map' map */
static inline __attribute__((always_inline)) char *
__d_path_local(const struct path *path, char *buf, int *buflen, int *error)
{
	char *res = buf + *buflen;
	struct task_struct *task;
	struct fs_struct *fs;

	task = (struct task_struct *)get_current_task();
	probe_read(&fs, sizeof(fs), _(&task->fs));
	*error = path_with_deleted(path, _(&fs->root), buf, &res, buflen);
	return res;
}

static inline __attribute__((always_inline)) int64_t
getcwd(struct msg_process *curr, __u32 offset, __u32 proc_pid, bool prealloc)
{
	struct task_struct *task = get_task_from_pid(proc_pid);
	__u32 orig_size = curr->size, orig_offset = offset;
	struct fs_struct *fs;
	u32 flags = 0;

	probe_read(&fs, sizeof(fs), _(&task->fs));
	if (!fs) {
		curr->flags |= EVENT_ERROR_CWD;
		return 0;
	}

	offset = get_full_path(_(&fs->pwd), curr, offset, &flags);
	curr->size = offset;
	// Unfortunate special case for '/' where nothing was added we need
	// to truncate with '\n' for parser.
	if (curr->size == orig_offset)
		curr->flags |= EVENT_ROOT_CWD;
	if (flags & UNRESOLVED_MOUNT_POINTS)
		curr->flags |= EVENT_ERROR_MOUNT_POINTS;
	if (flags & UNRESOLVED_PATH_COMPONENTS)
		curr->flags |= EVENT_ERROR_PATH_COMPONENTS;

	/* If the size was preallocated from user space side (ProcFS entry)
	 * then we need to keep the same size so we can find parent/child
	 * entries.
	 */
	if (prealloc)
		curr->size = orig_size;
	return 0;
}

static inline __attribute__((always_inline)) __u32 get_task_pid_vnr(void)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	int thread_pid_exists;
	unsigned int level;
	struct upid upid;
	struct pid *pid;
	int upid_sz;

	thread_pid_exists = bpf_core_field_exists(task->thread_pid);
	if (thread_pid_exists) {
		probe_read(&pid, sizeof(pid), _(&task->thread_pid));
		if (!pid) {
			return 0;
		}
	} else {
		struct pid_link link;
		int link_sz = bpf_core_field_size(task->pids);

		/* 4.14 verifier did not prune this branch even though we
		 * have the if (0) above after BTF exists check. So it will
		 * try to run this probe_read and throw an error. So lets
		 * sanitize it for the verifier.
		 */
		if (!thread_pid_exists)
			link_sz =
				24; // voodoo magic, hard-code 24 to init stack
		probe_read(&link, link_sz,
			   (void *)_(&task->pids) + (PIDTYPE_PID * link_sz));
		pid = link.pid;
	}
	upid_sz = bpf_core_field_size(pid->numbers[0]);
	probe_read(&level, sizeof(level), _(&pid->level));
	if (level < 1)
		return 0;
	probe_read(&upid, upid_sz,
		   (void *)_(&pid->numbers) + (level * upid_sz));
	return upid.nr;
}

static inline __attribute__((always_inline)) uint32_t
event_filename_builder(struct msg_process *curr, __u32 curr_pid, __u32 flags,
		       __u32 bin, void *filename)
{
	int64_t size = 0;
	uint32_t *value;
	char *earg;

	/* For now we set pathname on stack with zero initializer because its
	 * easy. We should push this into a map or do string compare directly
	 * to make it work for longer pathnames. For now lets get the mechanics
	 * working with short names.
	 */
	char pathname[256] = { 0 };

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
		flags |= EVENT_TRUNC_FILENAME;
	}
	curr->flags = flags;
	curr->pid = curr_pid;
	curr->nspid = get_task_pid_vnr();
	curr->ktime = ktime_get_ns();
	curr->size = size + offsetof(struct msg_process, args);

	probe_read_str(pathname, 255, filename);
	value = map_lookup_elem(&names_map, pathname);
	if (value)
		return *value;
	return bin;
}

#define PROBE_ARG_HEADER "%[index] = 0;"

#define PROBE_ARG_READ5                                                        \
	PROBE_ARG_READ                                                         \
	PROBE_ARG_READ                                                         \
	PROBE_ARG_READ                                                         \
	PROBE_ARG_READ                                                         \
	PROBE_ARG_READ

#define PROBE_ARG_READ10                                                       \
	PROBE_ARG_READ5                                                        \
	PROBE_ARG_READ5

#define PROBE_ARG_READ50                                                       \
	PROBE_ARG_READ10                                                       \
	PROBE_ARG_READ10                                                       \
	PROBE_ARG_READ10                                                       \
	PROBE_ARG_READ10                                                       \
	PROBE_ARG_READ10

/* The first argument is the command from cmdline but we already report the
 * filename so its redundant lets walk past it. Do we still need end check?
 * Left for now until we analyze a bit.
 */
#define PROBE_PAST_CMD                                                         \
	"r3 = *(u64 *)%[args];"                                                \
	"r3 += %[offset];"                                                     \
	"r4 = *(u64 *)%[end];"                                                 \
	"if r4 <= r3 goto %l[c];"                                              \
	"r4 = *(u32 *)(%[curr] + 0);"                                          \
	"if r4 s< 0 goto %l[a];"                                               \
	"if r4 s> " XSTR(                                                      \
		BUFFER) " goto %l[b];"                                         \
			"r1 = *(u64 *)%[earg];"                                \
			"r1 += r4;"                                            \
			"r2 = " XSTR(MAXARGLENGTH) ";"                         \
						   "call 45;"                  \
						   "if r0 s< 0 goto %l[a];"    \
						   "%[offset] += r0;"

#define PROBE_ARG_READ                                                         \
	"r3 = *(u64 *)%[args];"                                                \
	"r3 += %[offset];"                                                     \
	"r4 = *(u64 *)%[end];"                                                 \
	"if r4 <= r3 goto %l[c];"                                              \
	"r4 = *(u32 *)(%[curr] + 0);"                                          \
	"if r4 s< 0 goto %l[a];"                                               \
	"if r4 s> " XSTR(                                                      \
		BUFFER) " goto %l[b];"                                         \
			"r1 = *(u64 *)%[earg];"                                \
			"r1 += r4;"                                            \
			"r2 = " XSTR(                                          \
				MAXARGLENGTH) ";"                              \
					      "call 45;"                       \
					      "if r0 s< 0 goto %l[a];"         \
					      "%[offset] += r0;"               \
					      "r4 = *(u32 *)(%[curr] + 0);"    \
					      "r0 += r4;"                      \
					      "*(u32 *)(%[curr] + 0) = r0;"

/* To ensure reading args will work across multiple kernels and pass verifier we
 * code it as an asm block to make it friendly for verifiers. Otherwise, the C
 * code became far too fragile and even small refactors had potential to break
 * some kernel version with whatever set of fixes that kernel has. Not everyone
 * is even using LTS kernels so we get kernels with verifier in strange states.
 * I'm looking at you 4.15 kernel running in minikube!
 */
static inline __attribute__((always_inline)) void
probe_arg_read(struct msg_process *c, char *earg, char *args, char *end_args)
{
	int off = 0;

	asm volatile goto(PROBE_PAST_CMD PROBE_ARG_READ50
			  :
			  : [earg] "m"(earg), [args] "m"(args),
			    [end] "m"(end_args), [curr] "ri"(c),
			    [offset] "r"(off)
			  : "r0", "r1", "r2", "r3", "r4", "r5"
			  : a, b, c);
	c->flags |= EVENT_TRUNC_ARGS;
c:
	return;
b:
	c->flags |= EVENT_TRUNC_ARGS;
	return;
a:
	c->flags |= EVENT_ERROR_ARGS;
}

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
event_args_builder(struct msg_execve_event *event)
{
	struct task_struct *task = (struct task_struct *)get_current_task();
	struct msg_process *p, *c;
	struct mm_struct *mm;
	//int64_t base;

	/* Calculate absolute offset into buffer */
	c = &event->process;
	c->auid = get_auid();
	p = c;

	/* We use flags in asm to indicate overflow */
	compiler_barrier();
	probe_read(&mm, sizeof(mm), _(&task->mm));
	if (mm) {
		long unsigned int start_stack, end_stack;

		probe_read(&start_stack, sizeof(start_stack),
			   _(&mm->arg_start));
		probe_read(&end_stack, sizeof(start_stack), _(&mm->arg_end));
		if (start_stack && end_stack)
			probe_arg_read(c, (char *)p, (char *)start_stack,
				       (char *)end_stack);
	}
	//c->size -= base;
	return;
}

static inline __attribute__((always_inline)) void
event_set_clone(struct msg_process *pid)
{
	pid->flags |= EVENT_CLONE;
}

static inline __attribute__((always_inline)) void
get_caps(struct msg_capabilities *msg, struct task_struct *task)
{
	const struct cred *cred;

	probe_read(&cred, sizeof(cred), _(&task->real_cred));
	probe_read(&msg->effective, sizeof(__u64), _(&cred->cap_effective));
	probe_read(&msg->inheritable, sizeof(__u64), _(&cred->cap_inheritable));
	probe_read(&msg->permitted, sizeof(__u64), _(&cred->cap_permitted));
}

static inline __attribute__((always_inline)) void
get_namespaces(struct msg_ns *msg, struct task_struct *task)
{
	struct nsproxy *nsproxy;
	struct nsproxy nsp;

	probe_read(&nsproxy, sizeof(nsproxy), _(&task->nsproxy));
	probe_read(&nsp, sizeof(nsp), _(nsproxy));

	probe_read(&msg->uts_inum, sizeof(msg->uts_inum),
		   _(&nsp.uts_ns->ns.inum));
	probe_read(&msg->ipc_inum, sizeof(msg->ipc_inum),
		   _(&nsp.ipc_ns->ns.inum));
	probe_read(&msg->mnt_inum, sizeof(msg->mnt_inum),
		   _(&nsp.mnt_ns->ns.inum));
	{
		struct pid *p = 0;

		probe_read(&p, sizeof(p), _(&task->thread_pid));
		if (p) {
			int level = 0;
			struct upid up;

			probe_read(&level, sizeof(level), _(&p->level));
			probe_read(&up, sizeof(up), _(&p->numbers[level]));
			probe_read(&msg->pid_inum, sizeof(msg->pid_inum),
				   _(&up.ns->ns.inum));
		} else
			msg->pid_inum = 0;
	}
	probe_read(&msg->pid_for_children_inum,
		   sizeof(msg->pid_for_children_inum),
		   _(&nsp.pid_ns_for_children->ns.inum));
	probe_read(&msg->net_inum, sizeof(msg->net_inum),
		   _(&nsp.net_ns->ns.inum));

	// this also includes time_ns_for_children
	if (bpf_core_field_exists(nsproxy->time_ns)) {
		probe_read(&msg->time_inum, sizeof(msg->time_inum),
			   _(&nsp.time_ns->ns.inum));
		probe_read(&msg->time_for_children_inum,
			   sizeof(msg->time_for_children_inum),
			   _(&nsp.time_ns_for_children->ns.inum));
	}

	probe_read(&msg->cgroup_inum, sizeof(msg->cgroup_inum),
		   _(&nsp.cgroup_ns->ns.inum));
	{
		struct mm_struct *mm;
		struct user_namespace *user_ns;

		probe_read(&mm, sizeof(mm), _(&task->mm));
		probe_read(&user_ns, sizeof(user_ns), _(&mm->user_ns));
		probe_read(&msg->user_inum, sizeof(msg->user_inum),
			   _(&user_ns->ns.inum));
	}
}

/* Pahole bug does not convert to btf correctly with arbitrary byte holes not
 * near a cacheline. To work-around this we can specify a define with the
 * CGROUPS_OFFSET we read directly out of debug_info section. Note other
 * reads, subsys[], cgroup are the first element of the structure so we can
 * "just" read those. Then cid, kn, and name all appear to be before byte
 * holes on kernels I checked so leave them alone for now.
 *
 * Todo, fix pahole to avoid doing extra steps to lookup offsets.
 * Edit: pahole has been fixed need to update toolchain.
 */
static inline __attribute__((always_inline)) void
__event_get_task_info(struct msg_execve_event *msg, __u8 op, bool walker,
		      bool cwd_always)
{
	struct cgroup_subsys_state *subsys;
	struct msg_process *curr;
	struct task_struct *task;
	struct nsproxy *nsproxy;
	struct css_set *cgroups;
	struct kernfs_node *kn;
	struct cgroup *cgrp;
	struct net *net_ns;
	const char *name;

	msg->common.op = op;
	msg->common.ktime = ktime_get_ns();
	curr = &msg->process;

	if (cwd_always || curr->flags & EVENT_NEEDS_CWD) {
		__u32 offset;
		int err;
		bool prealloc = false;

		/* In the cwd always case we have no reserved memory for
		 * CWD so insert CWD directly after the curr->size. In
		 * EVENT_NEEDS_CWD case this is a procFS entry that we
		 * need to insert CWD for and memory has been reserved
		 * already. Finally if ERROR_CWD flag is set skip there
		 * is no point in continuing to bang on it if its not
		 * working.
		 */
		offset = curr->size;
		if (!cwd_always) {
			offset -= CWD_MAX + 1;
			prealloc = true;
		}
		if (!(curr->flags & EVENT_ERROR_CWD)) {
			err = getcwd(curr, offset, curr->pid, prealloc);
			if (!err)
				curr->flags = curr->flags & ~(EVENT_NEEDS_CWD |
							      EVENT_ERROR_CWD);
		}
	}
	if (curr->flags & EVENT_NEEDS_AUID) {
		__u32 flags = curr->flags & ~EVENT_NEEDS_AUID;

		curr->auid = get_auid();
		curr->flags = flags;
	}
	msg->common.size =
		offsetof(struct msg_execve_event, process) + curr->size;
	curr->uid = get_current_uid_gid();
	if (walker)
		curr->flags |= EVENT_TASK_WALK;

	task = (struct task_struct *)get_current_task();
	probe_read(&nsproxy, sizeof(nsproxy), _(&task->nsproxy));
	if (nsproxy) {
		probe_read(&net_ns, sizeof(net_ns), _(&nsproxy->net_ns));
		if (net_ns)
			probe_read(&msg->kube.net_ns, sizeof(msg->kube.net_ns),
				   _(&net_ns->ns.inum));
	}

	task = (struct task_struct *)get_current_task();
	probe_read(&cgroups, sizeof(cgroups), _(&task->cgroups));
	if (cgroups) {
		probe_read(&subsys, sizeof(subsys), _(&cgroups->subsys[0]));
		if (subsys) {
			probe_read(&cgrp, sizeof(cgrp), _(&subsys->cgroup));
			if (cgrp) {
				probe_read(&kn, sizeof(cgrp->kn), _(&cgrp->kn));
				if (kn) {
					probe_read(&name, sizeof(name),
						   _(&kn->name));
					if (name) {
						probe_read_str(
							msg->kube.docker_id,
							DOCKER_ID_LENGTH, name);
					} else {
						curr->flags |=
							EVENT_DOCKER_NAME_ERR;
					}
				}
				// else case we do not include error flag because it
				// indicates there is not a docker id. This is normal
				// in the case process is in host namespace.
			} else {
				curr->flags |= EVENT_DOCKER_SUBSYSCGRP_ERR;
			}
		} else {
			curr->flags |= EVENT_DOCKER_SUBSYS_ERR;
		}
	} else {
		curr->flags |= EVENT_DOCKER_CGROUPS_ERR;
	}
#ifdef BPF_FUNC_get_current_cgroup_id
	msg->kube.cgrpid = get_current_cgroup_id();
#endif
	get_caps(&(msg->caps), task);
	get_namespaces(&(msg->ns), task);
}
#endif
