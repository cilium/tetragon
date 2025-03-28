// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package bpf

import (
	"path/filepath"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/constants"
)

const (
	eventsMapName = "tcpmon_map"

	PERF_TYPE_SOFTWARE = 1

	PERF_SAMPLE_RAW          = 1 << 10
	PERF_COUNT_SW_BPF_OUTPUT = 10

	// BPF map type constants. Must match enum bpf_map_type from linux/bpf.h
	BPF_MAP_TYPE_UNSPEC              = 0
	BPF_MAP_TYPE_HASH                = 1
	BPF_MAP_TYPE_ARRAY               = 2
	BPF_MAP_TYPE_PROG_ARRAY          = 3
	BPF_MAP_TYPE_PERF_EVENT_ARRAY    = 4
	BPF_MAP_TYPE_PERCPU_HASH         = 5
	BPF_MAP_TYPE_PERCPU_ARRAY        = 6
	BPF_MAP_TYPE_STACK_TRACE         = 7
	BPF_MAP_TYPE_CGROUP_ARRAY        = 8
	BPF_MAP_TYPE_LRU_HASH            = 9
	BPF_MAP_TYPE_LRU_PERCPU_HASH     = 10
	BPF_MAP_TYPE_LPM_TRIE            = 11
	BPF_MAP_TYPE_ARRAY_OF_MAPS       = 12
	BPF_MAP_TYPE_HASH_OF_MAPS        = 13
	BPF_MAP_TYPE_DEVMAP              = 14
	BPF_MAP_TYPE_SOCKMAP             = 15
	BPF_MAP_TYPE_CPUMAP              = 16
	BPF_MAP_TYPE_XSKMAP              = 17
	BPF_MAP_TYPE_SOCKHASH            = 18
	BPF_MAP_TYPE_CGROUP_STORAGE      = 19
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20

	// BPF syscall command constants. Must match enum bpf_cmd from linux/bpf.h
	BPF_MAP_CREATE          = 0
	BPF_MAP_LOOKUP_ELEM     = 1
	BPF_MAP_UPDATE_ELEM     = 2
	BPF_MAP_DELETE_ELEM     = 3
	BPF_MAP_GET_NEXT_KEY    = 4
	BPF_PROG_LOAD           = 5
	BPF_OBJ_PIN             = 6
	BPF_OBJ_GET             = 7
	BPF_PROG_ATTACH         = 8
	BPF_PROG_DETACH         = 9
	BPF_PROG_TEST_RUN       = 10
	BPF_PROG_GET_NEXT_ID    = 11
	BPF_MAP_GET_NEXT_ID     = 12
	BPF_PROG_GET_FD_BY_ID   = 13
	BPF_MAP_GET_FD_BY_ID    = 14
	BPF_OBJ_GET_INFO_BY_FD  = 15
	BPF_PROG_QUERY          = 16
	BPF_RAW_TRACEPOINT_OPEN = 17
	BPF_BTF_LOAD            = 18
	BPF_BTF_GET_FD_BY_ID    = 19
	BPF_TASK_FD_QUERY       = 20

	// BPF syscall attach types
	BPF_CGROUP_INET_INGRESS     = 0
	BPF_CGROUP_INET_EGRESS      = 1
	BPF_CGROUP_INET_SOCK_CREATE = 2
	BPF_CGROUP_SOCK_OPS         = 3
	BPF_SK_SKB_STREAM_PARSER    = 4
	BPF_SK_SKB_STREAM_VERDICT   = 5
	BPF_CGROUP_DEVICE           = 6
	BPF_SK_MSG_VERDICT          = 7
	BPF_CGROUP_INET4_BIND       = 8
	BPF_CGROUP_INET6_BIND       = 9
	BPF_CGROUP_INET4_CONNECT    = 10
	BPF_CGROUP_INET6_CONNECT    = 11
	BPF_CGROUP_INET4_POST_BIND  = 12
	BPF_CGROUP_INET6_POST_BIND  = 13
	BPF_CGROUP_UDP4_SENDMSG     = 14
	BPF_CGROUP_UDP6_SENDMSG     = 15
	BPF_LIRC_MODE2              = 16
	BPF_FLOW_DISSECTOR          = 17
	BPF_CGROUP_SYSCTL           = 18
	BPF_CGROUP_UDP4_RECVMSG     = 19
	BPF_CGROUP_UDP6_RECVMSG     = 20

	// Flags for BPF_MAP_UPDATE_ELEM. Must match values from linux/bpf.h
	BPF_ANY     = 0
	BPF_NOEXIST = 1
	BPF_EXIST   = 2

	// Flags for BPF_MAP_CREATE. Must match values from linux/bpf.h
	BPF_F_NO_PREALLOC   = 1 << 0
	BPF_F_NO_COMMON_LRU = 1 << 1
	BPF_F_NUMA_NODE     = 1 << 2

	// Flags for BPF_PROG_QUERY
	BPF_F_QUERY_EFFECTVE = 1 << 0

	// Flags for accessing BPF object
	BPF_F_RDONLY = 1 << 3
	BPF_F_WRONLY = 1 << 4

	// Flag for stack_map, store build_id+offset instead of pointer
	BPF_F_STACK_BUILD_ID = 1 << 5

	// Build ID flags bit for perf_event_open
	PerfBitBuildId = constants.CBitFieldMaskBit34
)

type PerfEventConfig struct {
	NumCpus      int
	NumPages     int
	MapName      string
	Type         int
	Config       int
	SampleType   int
	WakeupEvents int
}

func GetNumPossibleCPUs() int {
	nCpus, err := ebpf.PossibleCPU()
	if err != nil {
		nCpus = runtime.NumCPU()
	}
	return nCpus
}

// DefaultPerfEventConfig returns the default perf event configuration. It
// relies on the map root to be set.
func DefaultPerfEventConfig() *PerfEventConfig {
	return &PerfEventConfig{
		MapName:      filepath.Join(MapPrefixPath(), eventsMapName),
		Type:         PERF_TYPE_SOFTWARE,
		Config:       PERF_COUNT_SW_BPF_OUTPUT,
		SampleType:   PERF_SAMPLE_RAW,
		WakeupEvents: 1,
		NumCpus:      GetNumPossibleCPUs(),
		NumPages:     128,
	}
}
