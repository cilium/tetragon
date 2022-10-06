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

typedef enum {
	DEPLOY_UNKNOWN = 0,
	DEPLOY_K8S = 1, // K8s deployment
	DEPLOY_CONTAINER = 2, // Container docker, podman, etc
	DEPLOY_SD_SERVICE = 10, // Systemd service
	DEPLOY_SD_USER = 11, // Systemd user session
} deploy_mode;

/* Tetragon runtime configuration */
struct tetragon_conf {
	deploy_mode mode; /* Tetragon deployment mode */
	__u32 loglevel; /* Tetragon log level */
	__u32 pid; /* Tetragon pid for debugging purpose */
	__u32 nspid; /* Tetragon pid in namespace for debugging purpose */
	__u32 tg_cgrp_hierarchy; /* Tetragon tracked hierarchy ID */
	__u32 tg_cgrp_subsys_idx; /* Tetragon tracked cgroup subsystem state index at compile time */
	__u32 tg_cgrp_level; /* Tetragon cgroup level */
	__u32 pad;
	__u64 tg_cgrpid; /* Tetragon current cgroup ID to avoid filtering blocking itself */
	__u64 cgrp_fs_magic; /* Cgroupv1 or Cgroupv2 */
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __s32);
	__type(value, struct tetragon_conf);
} tg_conf_map SEC(".maps");

#endif // __ENVIRON_CONF_
