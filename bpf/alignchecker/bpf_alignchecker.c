#define ALIGNCHECKER

#include "include/vmlinux.h"
#include "include/api.h"
#include "compiler.h"
#include "lib/bpf_event.h"
#include "lib/bpf_cred.h"
#include "process/retprobe_map.h"
#include "process/types/basic.h"
#include "policy_stats.h"

// event messages
struct msg_generic_kprobe _msg_generic_kprobe;
struct msg_execve_event _msg_execve_event;
struct msg_exit _msg_exit;
struct msg_test _msg_test;
struct msg_cgroup_event _msg_cgroup_event;
struct msg_cred _msg_cred;

// from maps
struct event _event;
struct msg_execve_key _msg_execve_key;
struct execve_map_value _execve_map_value;
struct event_config _event_config;
struct tetragon_conf _tetragon_conf;
struct cgroup_tracking_value _cgroup_tracking_value;
struct kernel_stats _kernel_stats;
struct policy_stats _policy_stats;
