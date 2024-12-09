// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Tetragon */
#ifndef BPF_ERRMETRICS_H__
#define BPF_ERRMETRICS_H__

#include "compiler.h"

// should match: pkg/errmetrics/map.go:MapKey
struct errmetrics_key {
	__u16 error;
	__u8 file_id;
	__u8 pad1;
	__u16 line_nr;
	__u16 pad2;
} __attribute__((packed));

FUNC_INLINE __u16
get_fileid__(const char *const fname)
{
#define fileid__(f, id)                  \
	if (!__builtin_strcmp(f, fname)) \
		return id;
#include "fileids.h"
#undef fileid__

	return 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
	__uint(max_entries, 1024);
	__type(key, struct errmetrics_key);
	__type(value, __u32); // counter, should match pkg/errmetrics/map.go:MapVal
} tg_errmetrics_map SEC(".maps");

FUNC_INLINE void
errmetrics_update(__u16 error, __u8 file_id, __u16 line_nr)
{
	__u32 *count;
	struct errmetrics_key key = {
		.error = error,
		.file_id = file_id,
		.line_nr = line_nr,
	};

	count = map_lookup_elem(&tg_errmetrics_map, &key);
	if (count) {
		*count += 1;
	} else {
		__u32 one = 1;

		map_update_elem(&tg_errmetrics_map, &key, &one, 0);
	}
}

#define xerrstr(x) errstr(x)
#define errstr(s)  "add " #s " to the ids list (fileids.h)"

#define compile_error(f)                                                                     \
	do {                                                                                 \
		extern __attribute__((__error__(xerrstr(f)))) void compile_time_error(void); \
		compile_time_error();                                                        \
	} while (0)

#define map_update_elem__errmetrics(m, k, v, f) ({         \
	int err;                                           \
	__u16 fileid = get_fileid__(__FILE__);             \
                                                           \
	if (!__builtin_constant_p(fileid) || !fileid)      \
		compile_error(__FILE__);                   \
	err = map_update_elem(m, k, v, f);                 \
	if (err)                                           \
		errmetrics_update(-err, fileid, __LINE__); \
	err;                                               \
})

#endif // BPF_ERRMETRICS_H__
