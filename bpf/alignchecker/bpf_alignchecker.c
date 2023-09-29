#define ALIGNCHECKER

#include "include/vmlinux.h"
#include "include/api.h"
#include "lib/bpf_event.h"
#include "lib/bpf_cred.h"
#include "process/retprobe_map.h"
#include "process/types/basic.h"

struct msg_generic_kprobe _1;
struct msg_execve_event _2;
struct msg_exit _3;
struct msg_test _4;
struct msg_cgroup_event _5;
struct msg_cred _6;
struct msg_cred_minimal _7;

// from maps
struct event _8;
struct msg_execve_key _9;
struct execve_map_value _10;
struct event_config _11;
struct tetragon_conf _12;
struct cgroup_tracking_value _13;
