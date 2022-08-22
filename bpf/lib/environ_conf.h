// SPDX-License-Identifier: GPL-2.0
/* Copyright Authors of Tetragon */

#ifndef __ENVIRON_CONF_
#define __ENVIRON_CONF_

/* bpf runtime log levels that follow Golang logrus levels
 * https://pkg.go.dev/github.com/sirupsen/logrus#Level
 */
enum {
	LOG_ERROR_LEVEL = 2,
	LOG_WARN_LEVEL = 3,
	LOG_INFO_LEVEL = 4,
	LOG_DEBUG_LEVEL = 5,
	LOG_TRACE_LEVEL = 6,
};

/* Tetragon running configuration */
struct tetragon_conf {
	__u32 mode; /* Tetragon deployment mode */
	__u32 loglevel; /* Tetragon log level */
	__u32 pid; /* Tetragon pid for debugging purpose */
	__u32 nspid; /* Tetragon pid in namespace for debugging purpose */
	__u32 tg_cgrp_level; /* Tetragon cgroup level */
	__u32 pad;
	__u64 tg_cgrpid; /* Tetragon current cgroup ID to avoid filtering blocking itself */
	__u64 cgrp_fs_magic; /* Cgroupv1 or Cgroupv2 */
};

struct bpf_map_def __attribute__((section("maps"), used)) tg_conf_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__s32),
	.value_size = sizeof(struct tetragon_conf),
	.max_entries = 1,
};

#endif // __ENVIRON_CONF_
