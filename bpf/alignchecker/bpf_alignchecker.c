#define ALIGNCHECKER

#include "include/vmlinux.h"
#include "include/api.h"
#include "lib/hubble_msg.h"
#include "process/retprobe_map.h"
#include "process/types/basic.h"

struct msg_generic_kprobe _1;
struct msg_execve_event _2;
struct msg_exit _3;
struct msg_test _4;
struct msg_cgroup_event _5;

// from maps
struct event _6;
struct msg_execve_key _7;
struct execve_map_value _8;
struct event_config _9;
struct tetragon_conf _10;
struct cgroup_tracking_value _11;
