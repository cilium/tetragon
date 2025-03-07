// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#ifndef __D_PATH__
#define __D_PATH__

#include "bpf_helpers.h"

#define ENAMETOOLONG 36 /* File name too long */

#define MAX_BUF_LEN 4096

/* __d_path_local flags */
// #define UNRESOLVED_MOUNT_POINTS	   0x01 // (deprecated)
// this error is returned by __d_path_local in the following cases:
// - the path walk did not conclude (too many dentry)
// - the path was too long to fit in the buffer
#define UNRESOLVED_PATH_COMPONENTS 0x02

#ifndef __V61_BPF_PROG
#ifdef __LARGE_BPF_PROG
#define PROBE_CWD_READ_ITERATIONS 128
#else
#define PROBE_CWD_READ_ITERATIONS 11
#endif
#else
#define PROBE_CWD_READ_ITERATIONS 2048
#endif

#define offsetof_btf(s, memb) ((size_t)((char *)_(&((s *)0)->memb) - (char *)0))

#define container_of_btf(ptr, type, member)                      \
	({                                                       \
		void *__mptr = (void *)(ptr);                    \
		((type *)(__mptr - offsetof_btf(type, member))); \
	})
struct buffer_heap_map_value {
	// Buffer need a bit more space here  because of the verifier. In
	// prepend_name unit tests, the verifier figures out that MAX_BUF_LEN is
	// enough and that the buffer_offset will not overflow, but in the real
	// use-case it looks like it's forgetting about that.
	unsigned char buf[MAX_BUF_LEN + 256];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct buffer_heap_map_value);
} buffer_heap_map SEC(".maps");

FUNC_INLINE struct mount *real_mount(struct vfsmount *mnt)
{
	return container_of_btf(mnt, struct mount, mnt);
}

FUNC_INLINE bool IS_ROOT(struct dentry *dentry)
{
	struct dentry *d_parent;

	probe_read(&d_parent, sizeof(d_parent), _(&dentry->d_parent));
	return (dentry == d_parent);
}

FUNC_INLINE bool hlist_bl_unhashed(const struct hlist_bl_node *h)
{
	struct hlist_bl_node **pprev;

	probe_read(&pprev, sizeof(pprev), _(&h->pprev));
	return !pprev;
}

FUNC_INLINE int d_unhashed(struct dentry *dentry)
{
	return hlist_bl_unhashed(_(&dentry->d_hash));
}

FUNC_INLINE int d_unlinked(struct dentry *dentry)
{
	return d_unhashed(dentry) && !IS_ROOT(dentry);
}

/*
 * Only called from path_with_deleted function before any path traversals.
 * In the current scenarios, always buflen will be 256 and namelen 10.
 * For this reason I will never return -ENAMETOOLONG.
 */
FUNC_INLINE int
prepend(char **buffer, int *buflen, const char *str, int namelen)
{
	*buflen -= namelen;
	if (*buflen < 0) // will never happen - check function comment
		return -ENAMETOOLONG;
	*buffer -= namelen;
	memcpy(*buffer, str, namelen);
	return 0;
}

struct cwd_read_data {
	struct dentry *root_dentry;
	struct vfsmount *root_mnt;
	char *bf;
	struct dentry *dentry;
	struct vfsmount *vfsmnt;
	struct mount *mnt;
	char *bptr;
	int blen;
	bool resolved;
};

FUNC_INLINE int
prepend_name(char *buf, char **bufptr, int *buflen, const char *name, u32 namelen)
{
	// contains 1 if the buffer is large enough to contain the whole name and a slash prefix
	bool write_slash = 1;

	u64 buffer_offset = (u64)(*bufptr) - (u64)buf;

	// Change name and namelen to fit in the buffer.
	// We prefer to store the part of it that fits rather than discard it.
	if (namelen >= *buflen) {
		name += namelen - *buflen;
		namelen = *buflen;
		write_slash = 0;
	}

	*buflen -= (namelen + write_slash);

	if (namelen + write_slash > buffer_offset)
		return -ENAMETOOLONG;

	buffer_offset -= (namelen + write_slash);

	// This will never happen. buffer_offset is the diff of the initial buffer pointer
	// with the current buffer pointer. This will be at max 4096 bytes (similar to the initial
	// size).
	// Needed to bound that for probe_read call.
	if (buffer_offset >= MAX_BUF_LEN)
		return -ENAMETOOLONG;

	if (write_slash)
		buf[buffer_offset] = '/';

	// This ensures that namelen is < 256, which is aligned with kernel's max dentry name length
	// that is 255 (https://elixir.bootlin.com/linux/v5.10/source/include/uapi/linux/limits.h#L12).
	// Needed to bound that for probe_read call.
	asm volatile("%[namelen] &= 0xff;\n"
		     : [namelen] "+r"(namelen));
	probe_read(buf + buffer_offset + write_slash, namelen * sizeof(char), name);

	*bufptr = buf + buffer_offset;
	return write_slash ? 0 : -ENAMETOOLONG;
}

FUNC_INLINE long cwd_read(struct cwd_read_data *data)
{
	struct qstr d_name;
	struct dentry *parent;
	struct dentry *vfsmnt_mnt_root;
	struct dentry *dentry = data->dentry;
	struct vfsmount *vfsmnt = data->vfsmnt;
	struct mount *mnt = data->mnt;
	int error;

	if (!(dentry != data->root_dentry || vfsmnt != data->root_mnt)) {
		data->resolved =
			true; // resolved all path components successfully
		return 1;
	}

	probe_read(&vfsmnt_mnt_root, sizeof(vfsmnt_mnt_root),
		   _(&vfsmnt->mnt_root));
	if (dentry == vfsmnt_mnt_root || IS_ROOT(dentry)) {
		struct mount *parent;

		probe_read(&parent, sizeof(parent), _(&mnt->mnt_parent));

		/* Global root? */
		if (data->mnt != parent) {
			probe_read(&data->dentry, sizeof(data->dentry),
				   _(&mnt->mnt_mountpoint));
			data->mnt = parent;
			data->vfsmnt = _(&parent->mnt);
			return 0;
		}
		// resolved all path components successfully
		data->resolved = true;
		return 1;
	}
	probe_read(&parent, sizeof(parent), _(&dentry->d_parent));
	probe_read(&d_name, sizeof(d_name), _(&dentry->d_name));
	error = prepend_name(data->bf, &data->bptr, &data->blen,
			     (const char *)d_name.name, d_name.len);
	// This will happen where the dentry name does not fit in the buffer.
	// We will stop the loop with resolved == false and later we will
	// set the proper value in error before function return.
	if (error)
		return 1;

	data->dentry = parent;
	return 0;
}

#ifdef __V61_BPF_PROG
static long cwd_read_v61(__u32 index, void *data)
{
	return cwd_read(data);
}
#endif

FUNC_INLINE int
prepend_path(const struct path *path, const struct path *root, char *bf,
	     char **buffer, int *buflen)
{
	struct cwd_read_data data = {
		.bf = bf,
		.bptr = *buffer,
		.blen = *buflen,
	};
	int error = 0;

	probe_read(&data.root_dentry, sizeof(data.root_dentry),
		   _(&root->dentry));
	probe_read(&data.root_mnt, sizeof(data.root_mnt), _(&root->mnt));
	probe_read(&data.dentry, sizeof(data.dentry), _(&path->dentry));
	probe_read(&data.vfsmnt, sizeof(data.vfsmnt), _(&path->mnt));
	data.mnt = real_mount(data.vfsmnt);

#ifndef __V61_BPF_PROG
#pragma unroll
	for (int i = 0; i < PROBE_CWD_READ_ITERATIONS; ++i) {
		if (cwd_read(&data))
			break;
	}
#else
	loop(PROBE_CWD_READ_ITERATIONS, cwd_read_v61, (void *)&data, 0);
#endif /* __V61_BPF_PROG */

	if (data.bptr == *buffer) {
		*buflen = 0;
		return 0;
	}
	if (!data.resolved)
		error = UNRESOLVED_PATH_COMPONENTS;
	*buffer = data.bptr;
	*buflen = data.blen;
	return error;
}

FUNC_INLINE int
path_with_deleted(const struct path *path, const struct path *root, char *bf,
		  char **buf, int *buflen)
{
	struct dentry *dentry;

	probe_read(&dentry, sizeof(dentry), _(&path->dentry));
	if (d_unlinked(dentry)) {
		int error = prepend(buf, buflen, " (deleted)", 10);

		if (error) // will never happen as prepend will never return a value != 0
			return error;
	}
	return prepend_path(path, root, bf, buf, buflen);
}

/*
 * This function returns the path of a dentry and works in a similar
 * way to Linux d_path function (https://elixir.bootlin.com/linux/v5.10/source/fs/d_path.c#L262).
 *
 * Input variables:
 * - 'path' is a pointer to a dentry path that we want to resolve
 * - 'buf' is the buffer where the path will be stored (this should be always the value of 'buffer_heap_map' map)
 * - 'buflen' is the available buffer size to store the path (now 256 in all cases, maybe we can increase that further)
 *
 * Input buffer layout:
 * <--        buflen         -->
 * -----------------------------
 * |                           |
 * -----------------------------
 * ^
 * |
 * buf
 *
 *
 * Output variables:
 * - 'buf' is where the path is stored (>= compared to the input argument)
 * - 'buflen' the size of the resolved path (0 < buflen <= 256). Will not be negative. If buflen == 0 nothing is written to the buffer.
 * - 'error' 0 in case of success or UNRESOLVED_PATH_COMPONENTS in the case where the path is larger than the provided buffer.
 *
 * Output buffer layout:
 * <--   buflen  -->
 * -----------------------------
 * |                /etc/passwd|
 * -----------------------------
 *                 ^
 *                 |
 *                buf
 *
 * ps. The size of the path will be (initial value of buflen) - (return value of buflen) if (buflen != 0)
 */
FUNC_INLINE char *
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

/*
 * Entry point to the codepath used for path resolution.
 *
 * This function allocates a buffer from 'buffer_heap_map' map and calls
 * __d_path_local. After __d_path_local returns, it also does the appropriate
 * calculations on the buffer size (check __d_path_local comment).
 *
 * Returns the buffer where the path is stored. 'buflen' is the size of the
 * resolved path (0 < buflen <= 256) and will not be negative. If buflen == 0
 * nothing is written to the buffer (still the value to the buffer is valid).
 * 'error' is 0 in case of success or UNRESOLVED_PATH_COMPONENTS in the case
 * where the path is larger than the provided buffer.
 */
FUNC_INLINE char *
d_path_local(const struct path *path, int *buflen, int *error)
{
	int zero = 0;
	char *buffer = 0;

	buffer = map_lookup_elem(&buffer_heap_map, &zero);
	if (!buffer)
		return 0;

	*buflen = MAX_BUF_LEN;
	buffer = __d_path_local(path, buffer, buflen, error);
	if (*buflen > 0)
		*buflen = MAX_BUF_LEN - *buflen;

	return buffer;
}
#endif /* __D_PATH__ */
