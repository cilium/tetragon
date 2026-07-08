// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package encoder

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/sryoya/protorand"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/api/v1/tetragon/codegen/helpers"
)

func TestCompactEncoder_InvalidEventToString(t *testing.T) {
	p := NewCompactEncoder(os.Stdout, Never, false, false, false)

	// should fail if the event field is nil.
	_, err := p.EventToString(&tetragon.GetEventsResponse{})
	require.Error(t, err)
}

func TestCompactEncoder_ExecEventToString(t *testing.T) {
	p := NewCompactEncoder(os.Stdout, Never, false, false, false)

	// should fail if the process field is nil.
	_, err := p.EventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExec{
			ProcessExec: &tetragon.ProcessExec{},
		},
	})
	require.Error(t, err)

	// without pod info
	result, err := p.EventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExec{
			ProcessExec: &tetragon.ProcessExec{
				Process: &tetragon.Process{
					Binary:    "/usr/bin/curl",
					Arguments: "cilium.io",
				},
			},
		},
		NodeName: "my-node",
	})
	require.NoError(t, err)
	assert.Equal(t, "🚀 process my-node /usr/bin/curl cilium.io", result)

	// with pod info
	result, err = p.EventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExec{
			ProcessExec: &tetragon.ProcessExec{
				Process: &tetragon.Process{
					Binary:    "/usr/bin/curl",
					Arguments: "cilium.io",
					Pod: &tetragon.Pod{
						Namespace: "kube-system",
						Name:      "tetragon",
					},
				},
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "🚀 process kube-system/tetragon /usr/bin/curl cilium.io", result)
}

func TestCompactEncoder_ExitEventToString(t *testing.T) {
	p := NewCompactEncoder(os.Stdout, Never, false, false, false)

	// should fail if the process field is nil.
	_, err := p.EventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExit{
			ProcessExit: &tetragon.ProcessExit{},
		},
	})
	require.Error(t, err)

	// with status
	result, err := p.EventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExit{
			ProcessExit: &tetragon.ProcessExit{
				Process: &tetragon.Process{
					Binary:    "/usr/bin/curl",
					Arguments: "cilium.io",
					Pod: &tetragon.Pod{
						Namespace: "kube-system",
						Name:      "tetragon",
					},
				},
				Status: 1,
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "💥 exit    kube-system/tetragon /usr/bin/curl cilium.io 1", result)

	// with signal
	result, err = p.EventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExit{
			ProcessExit: &tetragon.ProcessExit{
				Process: &tetragon.Process{
					Binary:    "/usr/bin/curl",
					Arguments: "cilium.io",
					Pod: &tetragon.Pod{
						Namespace: "kube-system",
						Name:      "tetragon",
					},
				},
				Signal: "SIGKILL",
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "💥 exit    kube-system/tetragon /usr/bin/curl cilium.io SIGKILL", result)
}

func TestCompactEncoder_KprobeEventToString(t *testing.T) {
	p := NewCompactEncoder(os.Stdout, Never, false, false, false)

	// should fail without process field
	_, err := p.EventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &tetragon.ProcessKprobe{
				FunctionName: "unhandled_function",
			},
		},
	})
	require.Error(t, err)

	// unknown function
	result, err := p.EventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &tetragon.ProcessKprobe{
				Process: &tetragon.Process{
					Binary: "/usr/bin/curl",
					Pod: &tetragon.Pod{
						Namespace: "kube-system",
						Name:      "tetragon",
					},
				},
				FunctionName: "unhandled_function",
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "❓ syscall kube-system/tetragon /usr/bin/curl unhandled_function", result)

}

func TestCompactEncoder_KprobeOpenEventToString(t *testing.T) {
	p := NewCompactEncoder(os.Stdout, Never, false, false, false)

	// open without args
	result, err := p.EventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &tetragon.ProcessKprobe{
				Process: &tetragon.Process{
					Binary: "/usr/bin/curl",
					Pod: &tetragon.Pod{
						Namespace: "kube-system",
						Name:      "tetragon",
					},
				},
				FunctionName: "fd_install",
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "📬 open    kube-system/tetragon /usr/bin/curl ", result)

	// open with args
	result, err = p.EventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &tetragon.ProcessKprobe{
				Process: &tetragon.Process{
					Binary: "/usr/bin/curl",
					Pod: &tetragon.Pod{
						Namespace: "kube-system",
						Name:      "tetragon",
					},
				},
				FunctionName: "fd_install",
				Args: []*tetragon.KprobeArgument{
					nil,
					{Arg: &tetragon.KprobeArgument_FileArg{FileArg: &tetragon.KprobeFile{Path: "/etc/password"}}},
				},
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "📬 open    kube-system/tetragon /usr/bin/curl /etc/password", result)
}

func TestCompactEncoder_KprobeWriteEventToString(t *testing.T) {
	p := NewCompactEncoder(os.Stdout, Never, false, false, false)

	// write without args
	result, err := p.EventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &tetragon.ProcessKprobe{
				Process: &tetragon.Process{
					Binary: "/usr/bin/curl",
					Pod: &tetragon.Pod{
						Namespace: "kube-system",
						Name:      "tetragon",
					},
				},
				FunctionName: "__x64_sys_write",
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "📝 write   kube-system/tetragon /usr/bin/curl  ", result)

	// write with args
	result, err = p.EventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &tetragon.ProcessKprobe{
				Process: &tetragon.Process{
					Binary: "/usr/bin/curl",
					Pod: &tetragon.Pod{
						Namespace: "kube-system",
						Name:      "tetragon",
					},
				},
				FunctionName: "__x64_sys_write",
				Args: []*tetragon.KprobeArgument{
					{Arg: &tetragon.KprobeArgument_FileArg{FileArg: &tetragon.KprobeFile{Path: "/etc/password"}}},
					nil,
					{Arg: &tetragon.KprobeArgument_SizeArg{SizeArg: 1234}},
				},
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "📝 write   kube-system/tetragon /usr/bin/curl /etc/password 1234 bytes", result)
}

func TestCompactEncoder_KprobeCloseEventToString(t *testing.T) {
	p := NewCompactEncoder(os.Stdout, Never, false, false, false)

	// open without args
	result, err := p.EventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &tetragon.ProcessKprobe{
				Process: &tetragon.Process{
					Binary: "/usr/bin/curl",
					Pod: &tetragon.Pod{
						Namespace: "kube-system",
						Name:      "tetragon",
					},
				},
				FunctionName: "__x64_sys_close",
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "📪 close   kube-system/tetragon /usr/bin/curl ", result)

	// open with args
	result, err = p.EventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &tetragon.ProcessKprobe{
				Process: &tetragon.Process{
					Binary: "/usr/bin/curl",
					Pod: &tetragon.Pod{
						Namespace: "kube-system",
						Name:      "tetragon",
					},
				},
				FunctionName: "__x64_sys_close",
				Args: []*tetragon.KprobeArgument{
					{Arg: &tetragon.KprobeArgument_FileArg{FileArg: &tetragon.KprobeFile{Path: "/etc/password"}}},
				},
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "📪 close   kube-system/tetragon /usr/bin/curl /etc/password", result)
}

func TestCompactEncoder_KprobeBPFEventToString(t *testing.T) {
	p := NewCompactEncoder(os.Stdout, Never, false, false, false)

	// bpf with no args
	result, err := p.EventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &tetragon.ProcessKprobe{
				Process: &tetragon.Process{
					Binary: "/usr/bin/bpftool",
					Pod: &tetragon.Pod{
						Namespace: "kube-system",
						Name:      "tetragon",
					},
				},
				FunctionName: "bpf_check",
			},
		}})
	require.NoError(t, err)
	assert.Equal(t, "🐝 bpf_load kube-system/tetragon /usr/bin/bpftool ", result)

	// bpf with args
	result, err = p.EventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &tetragon.ProcessKprobe{
				Process: &tetragon.Process{
					Binary: "/usr/bin/bpftool",
					Pod: &tetragon.Pod{
						Namespace: "kube-system",
						Name:      "tetragon",
					},
				},
				FunctionName: "bpf_check",
				Args: []*tetragon.KprobeArgument{
					{Arg: &tetragon.KprobeArgument_BpfAttrArg{
						BpfAttrArg: &tetragon.KprobeBpfAttr{
							ProgType: "BPF_PROG_TYPE_KPROBE",
							InsnCnt:  2048,
							ProgName: "amazing-program",
						},
					},
					},
				},
			},
		}})
	require.NoError(t, err)
	assert.Equal(t, "🐝 bpf_load kube-system/tetragon /usr/bin/bpftool BPF_PROG_TYPE_KPROBE amazing-program instruction count 2048", result)
}

func TestCompactEncoder_KprobePerfEventAllocEventToString(t *testing.T) {
	p := NewCompactEncoder(os.Stdout, Never, false, false, false)

	// perf event alloc with no args
	result, err := p.EventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &tetragon.ProcessKprobe{
				Process: &tetragon.Process{
					Binary: "/usr/bin/bpftool",
					Pod: &tetragon.Pod{
						Namespace: "kube-system",
						Name:      "tetragon",
					},
				},
				FunctionName: "security_perf_event_alloc",
			},
		}})
	require.NoError(t, err)
	assert.Equal(t, "🐝 perf_event_alloc kube-system/tetragon /usr/bin/bpftool ", result)

	// perf event alloc with args
	result, err = p.EventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &tetragon.ProcessKprobe{
				Process: &tetragon.Process{
					Binary: "/usr/bin/bpftool",
					Pod: &tetragon.Pod{
						Namespace: "kube-system",
						Name:      "tetragon",
					},
				},
				FunctionName: "security_perf_event_alloc",
				Args: []*tetragon.KprobeArgument{
					{Arg: &tetragon.KprobeArgument_PerfEventArg{
						PerfEventArg: &tetragon.KprobePerfEvent{
							KprobeFunc: "commit_creds",
							Type:       "PERF_TYPE_TRACEPOINT",
						},
					},
					},
				},
			},
		}})
	require.NoError(t, err)
	assert.Equal(t, "🐝 perf_event_alloc kube-system/tetragon /usr/bin/bpftool PERF_TYPE_TRACEPOINT commit_creds", result)
}

func TestCompactEncoder_KprobeBPFMapAllocEventToString(t *testing.T) {
	p := NewCompactEncoder(os.Stdout, Never, false, false, false)

	// bpf map with no args
	result, err := p.EventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &tetragon.ProcessKprobe{
				Process: &tetragon.Process{
					Binary: "/usr/bin/bpftool",
					Pod: &tetragon.Pod{
						Namespace: "kube-system",
						Name:      "tetragon",
					},
				},
				FunctionName: "security_bpf_map_alloc",
			},
		}})
	require.NoError(t, err)
	assert.Equal(t, "🗺 bpf_map_create kube-system/tetragon /usr/bin/bpftool ", result)

	// bpf map with args
	result, err = p.EventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &tetragon.ProcessKprobe{
				Process: &tetragon.Process{
					Binary: "/usr/bin/bpftool",
					Pod: &tetragon.Pod{
						Namespace: "kube-system",
						Name:      "tetragon",
					},
				},
				FunctionName: "security_bpf_map_alloc",
				Args: []*tetragon.KprobeArgument{
					{Arg: &tetragon.KprobeArgument_BpfMapArg{
						BpfMapArg: &tetragon.KprobeBpfMap{
							MapType:    "BPF_MAP_TYPE_HASH",
							KeySize:    8,
							ValueSize:  8,
							MaxEntries: 1024,
							MapName:    "amazing-map",
						},
					},
					},
				},
			},
		}})
	require.NoError(t, err)
	assert.Equal(t, "🗺 bpf_map_create kube-system/tetragon /usr/bin/bpftool BPF_MAP_TYPE_HASH amazing-map key size 8 value size 8 max entries 1024", result)
}

func TestCompactEncoder_KprobeBPFMapCreateEventToString(t *testing.T) {
	p := NewCompactEncoder(os.Stdout, Never, false, false, false)

	// bpf map with no args
	result, err := p.EventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &tetragon.ProcessKprobe{
				Process: &tetragon.Process{
					Binary: "/usr/bin/bpftool",
					Pod: &tetragon.Pod{
						Namespace: "kube-system",
						Name:      "tetragon",
					},
				},
				FunctionName: "security_bpf_map_create",
			},
		}})
	require.NoError(t, err)
	assert.Equal(t, "🗺 bpf_map_create kube-system/tetragon /usr/bin/bpftool ", result)

	// bpf map with args
	result, err = p.EventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &tetragon.ProcessKprobe{
				Process: &tetragon.Process{
					Binary: "/usr/bin/bpftool",
					Pod: &tetragon.Pod{
						Namespace: "kube-system",
						Name:      "tetragon",
					},
				},
				FunctionName: "security_bpf_map_create",
				Args: []*tetragon.KprobeArgument{
					{Arg: &tetragon.KprobeArgument_BpfMapArg{
						BpfMapArg: &tetragon.KprobeBpfMap{
							MapType:    "BPF_MAP_TYPE_HASH",
							KeySize:    8,
							ValueSize:  8,
							MaxEntries: 1024,
							MapName:    "amazing-map",
						},
					},
					},
				},
			},
		}})
	require.NoError(t, err)
	assert.Equal(t, "🗺 bpf_map_create kube-system/tetragon /usr/bin/bpftool BPF_MAP_TYPE_HASH amazing-map key size 8 value size 8 max entries 1024", result)
}

func TestCompactEncoder_Encode(t *testing.T) {
	var b bytes.Buffer
	p := NewCompactEncoder(&b, Never, false, false, false)

	// invalid event
	err := p.Encode(nil)
	require.Error(t, err)

	// more invalid event
	err = p.Encode(&tetragon.GetEventsResponse{})
	require.Error(t, err)

	// valid event
	err = p.Encode(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExec{
			ProcessExec: &tetragon.ProcessExec{
				Process: &tetragon.Process{
					Binary:    "/usr/bin/curl",
					Arguments: "cilium.io",
					Pod: &tetragon.Pod{
						Namespace: "kube-system",
						Name:      "tetragon",
					},
				},
			},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "🚀 process kube-system/tetragon /usr/bin/curl cilium.io\n", b.String())
}

func TestCompactEncoder_EncodeWithTimestamp(t *testing.T) {
	var b bytes.Buffer
	p := NewCompactEncoder(&b, Never, true, false, false)

	// invalid event
	err := p.Encode(nil)
	require.Error(t, err)

	// more invalid event
	err = p.Encode(&tetragon.GetEventsResponse{})
	require.Error(t, err)

	// valid event
	err = p.Encode(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExec{
			ProcessExec: &tetragon.ProcessExec{
				Process: &tetragon.Process{
					Binary:    "/usr/bin/curl",
					Arguments: "cilium.io",
					Pod: &tetragon.Pod{
						Namespace: "kube-system",
						Name:      "tetragon",
					},
				},
			},
		},
		Time: &timestamppb.Timestamp{},
	})
	require.NoError(t, err)
	assert.Equal(t, "1970-01-01T00:00:00.000000000Z 🚀 process kube-system/tetragon /usr/bin/curl cilium.io\n", b.String())
}

func TestCompactEncoder_EscapeSpecialCharacters(t *testing.T) {
	p := NewCompactEncoder(os.Stdout, Never, false, false, false)

	t.Run("binary", func(t *testing.T) {
		result, err := p.EventToString(&tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{
					Process: &tetragon.Process{
						Binary:    "/usr/bin/\x1b[31mmalicious\x1b[0m",
						Arguments: "normal-args",
						Pod: &tetragon.Pod{
							Namespace: "kube-system",
							Name:      "tetragon",
						},
					},
				},
			},
		})
		require.NoError(t, err)
		assert.Contains(t, result, "\"/usr/bin/\\x1b[31mmalicious\\x1b[0m\"")
		assert.NotContains(t, result, "\x1b")
	})

	t.Run("args", func(t *testing.T) {
		result, err := p.EventToString(&tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{
					Process: &tetragon.Process{
						Binary:    "/bin/sh",
						Arguments: "echo \x00null\rbyte",
						Pod: &tetragon.Pod{
							Namespace: "default",
							Name:      "pod",
						},
					},
				},
			},
		})
		require.NoError(t, err)
		assert.Contains(t, result, "\"echo \\x00null\\rbyte\"")
		assert.NotContains(t, result, "\x00")
		assert.NotContains(t, result, "\r")
	})

	t.Run("hostname", func(t *testing.T) {
		result, err := p.EventToString(&tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{
					Process: &tetragon.Process{
						Binary:    "/usr/bin/test",
						Arguments: "args",
					},
				},
			},
			NodeName: "host\nwith\nnewlines",
		})
		require.NoError(t, err)
		// Verify hostname is escaped when no pod info is present
		assert.Contains(t, result, "\"host\\nwith\\nnewlines\"")
		assert.NotContains(t, result, "host\nwith\nnewlines")
	})

	t.Run("file", func(t *testing.T) {
		result, err := p.EventToString(&tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessKprobe{
				ProcessKprobe: &tetragon.ProcessKprobe{
					Process: &tetragon.Process{
						Binary: "/usr/bin/cat",
						Pod: &tetragon.Pod{
							Namespace: "default",
							Name:      "test",
						},
					},
					FunctionName: "fd_install",
					Args: []*tetragon.KprobeArgument{
						nil,
						{Arg: &tetragon.KprobeArgument_FileArg{FileArg: &tetragon.KprobeFile{Path: "/tmp/file\nwith\nnewlines"}}},
					},
				},
			},
		})
		require.NoError(t, err)
		assert.Contains(t, result, "\"/tmp/file\\nwith\\nnewlines\"")
		assert.NotContains(t, result, "/tmp/file\nwith\nnewlines")
	})

	t.Run("cgroup", func(t *testing.T) {
		result, err := p.EventToString(&tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessThrottle{
				ProcessThrottle: &tetragon.ProcessThrottle{
					Type:   tetragon.ThrottleType_THROTTLE_START,
					Cgroup: "/sys/fs/cgroup\nmalicious",
				},
			},
		})
		require.NoError(t, err)
		assert.Contains(t, result, "\"/sys/fs/cgroup\\nmalicious\"")
		assert.NotContains(t, result, "/sys/fs/cgroup\nmalicious")
	})

	t.Run("loader", func(t *testing.T) {
		result, err := p.EventToString(&tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessLoader{
				ProcessLoader: &tetragon.ProcessLoader{
					Process: &tetragon.Process{
						Binary: "/usr/bin/loader",
						Pod: &tetragon.Pod{
							Namespace: "default",
							Name:      "test",
						},
					},
					Path: "/lib/evil\x1b[31m.so",
				},
			},
		})
		require.NoError(t, err)
		assert.Contains(t, result, "\"/lib/evil\\x1b[31m.so\"")
		assert.NotContains(t, result, "\x1b")
	})

	t.Run("stringarg", func(t *testing.T) {
		result, err := p.EventToString(&tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessKprobe{
				ProcessKprobe: &tetragon.ProcessKprobe{
					Process: &tetragon.Process{
						Binary: "/usr/bin/cat",
						Pod: &tetragon.Pod{
							Namespace: "default",
							Name:      "test",
						},
					},
					FunctionName: "sys_openat",
					Args: []*tetragon.KprobeArgument{
						nil,
						{Arg: &tetragon.KprobeArgument_StringArg{StringArg: "/etc/bad\nfile"}},
					},
				},
			},
		})
		require.NoError(t, err)
		assert.Contains(t, result, "\"/etc/bad\\nfile\"")
		assert.NotContains(t, result, "/etc/bad\nfile")
	})

	t.Run("filearg", func(t *testing.T) {
		result, err := p.EventToString(&tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessKprobe{
				ProcessKprobe: &tetragon.ProcessKprobe{
					Process: &tetragon.Process{
						Binary: "/usr/bin/write",
						Pod: &tetragon.Pod{
							Namespace: "default",
							Name:      "test",
						},
					},
					FunctionName: "__x64_sys_write",
					Args: []*tetragon.KprobeArgument{
						{Arg: &tetragon.KprobeArgument_FileArg{
							FileArg: &tetragon.KprobeFile{Path: "/var/log/bad\rfile"},
						}},
					},
				},
			},
		})
		require.NoError(t, err)
		assert.Contains(t, result, "\"/var/log/bad\\rfile\"")
		assert.NotContains(t, result, "\r")
	})

	t.Run("patharg", func(t *testing.T) {
		result, err := p.EventToString(&tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessKprobe{
				ProcessKprobe: &tetragon.ProcessKprobe{
					Process: &tetragon.Process{
						Binary: "/usr/bin/truncate",
						Pod: &tetragon.Pod{
							Namespace: "default",
							Name:      "test",
						},
					},
					FunctionName: "security_path_truncate",
					Args: []*tetragon.KprobeArgument{
						{Arg: &tetragon.KprobeArgument_PathArg{
							PathArg: &tetragon.KprobePath{Path: "/data/bad\nfile"},
						}},
					},
				},
			},
		})
		require.NoError(t, err)
		assert.Contains(t, result, "\"/data/bad\\nfile\"")
		assert.NotContains(t, result, "/data/bad\nfile")
	})

	t.Run("uprobe", func(t *testing.T) {
		result, err := p.EventToString(&tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessUprobe{
				ProcessUprobe: &tetragon.ProcessUprobe{
					Process: &tetragon.Process{
						Binary: "/usr/bin/test",
						Pod: &tetragon.Pod{
							Namespace: "default",
							Name:      "test",
						},
					},
					Path:   "/lib/\x1b[31mevil\x1b[0m.so",
					Symbol: "function_name",
				},
			},
		})
		require.NoError(t, err)
		assert.Contains(t, result, "\"/lib/\\x1b[31mevil\\x1b[0m.so\"")
		assert.NotContains(t, result, "\x1b")
	})

	t.Run("symbol", func(t *testing.T) {
		result, err := p.EventToString(&tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessUprobe{
				ProcessUprobe: &tetragon.ProcessUprobe{
					Process: &tetragon.Process{
						Binary: "/usr/bin/test",
						Pod: &tetragon.Pod{
							Namespace: "default",
							Name:      "test",
						},
					},
					Path:   "/lib/test.so",
					Symbol: "func\nname",
				},
			},
		})
		require.NoError(t, err)
		assert.Contains(t, result, "\"func\\nname\"")
		assert.NotContains(t, result, "func\nname")
	})

	t.Run("usdt", func(t *testing.T) {
		result, err := p.EventToString(&tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessUsdt{
				ProcessUsdt: &tetragon.ProcessUsdt{
					Process: &tetragon.Process{
						Binary: "/usr/bin/test",
						Pod: &tetragon.Pod{
							Namespace: "default",
							Name:      "test",
						},
					},
					Path:     "/usr/lib/bad\x00path",
					Provider: "provider",
					Name:     "probe",
				},
			},
		})
		require.NoError(t, err)
		assert.Contains(t, result, "\"/usr/lib/bad\\x00path\"")
		assert.NotContains(t, result, "\x00")
	})

	t.Run("provider", func(t *testing.T) {
		result, err := p.EventToString(&tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessUsdt{
				ProcessUsdt: &tetragon.ProcessUsdt{
					Process: &tetragon.Process{
						Binary: "/usr/bin/test",
						Pod: &tetragon.Pod{
							Namespace: "default",
							Name:      "test",
						},
					},
					Path:     "/usr/lib/test.so",
					Provider: "prov\nider",
					Name:     "probe",
				},
			},
		})
		require.NoError(t, err)
		assert.Contains(t, result, "\"prov\\nider\"")
		assert.NotContains(t, result, "prov\nider")
	})

	t.Run("name", func(t *testing.T) {
		result, err := p.EventToString(&tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessUsdt{
				ProcessUsdt: &tetragon.ProcessUsdt{
					Process: &tetragon.Process{
						Binary: "/usr/bin/test",
						Pod: &tetragon.Pod{
							Namespace: "default",
							Name:      "test",
						},
					},
					Path:     "/usr/lib/test.so",
					Provider: "provider",
					Name:     "probe\tname",
				},
			},
		})
		require.NoError(t, err)
		assert.Contains(t, result, "\"probe\\tname\"")
		assert.NotContains(t, result, "\t")
	})
}

func FuzzProtojsonCompatibility(f *testing.F) {
	for _, n := range []int64{
		1337,
		78776406,
		56343416,
		68876713,
		51156281,
		45544244,
		4011756,
	} {
		f.Add(n)
	}
	f.Fuzz(func(t *testing.T, seed int64) {
		pr := protorand.New()
		pr.Seed(seed)
		ev := &tetragon.GetEventsResponse{}
		msg, err := pr.Gen(ev)
		require.NoError(t, err)

		var buf1 bytes.Buffer
		protojsonEncoder := NewProtojsonEncoder(&buf1)
		err = protojsonEncoder.Encode(msg)
		require.NoError(t, err)

		var buf2 bytes.Buffer
		jsonEncoder := json.NewEncoder(&buf2)
		err = jsonEncoder.Encode(msg)
		require.NoError(t, err)

		msgProtojson := &tetragon.GetEventsResponse{}
		err = protojson.Unmarshal(buf2.Bytes(), msgProtojson)
		require.NoError(t, err)
		msgJson := &tetragon.GetEventsResponse{}
		err = json.Unmarshal(buf2.Bytes(), msgJson)
		require.NoError(t, err)

		assert.True(t, proto.Equal(msgJson, msgProtojson))
		assert.True(t, proto.Equal(msg, msgProtojson))
	})
}

func FuzzCompactEncoder(f *testing.F) {
	for _, n := range []int64{
		1337,
		78776406,
		56343416,
		68876713,
		51156281,
		45544244,
		4011756,
	} {
		for _, cm := range []uint8{0, 1, 2} {
			for _, ts := range []bool{true, false} {
				for _, st := range []bool{true, false} {
					f.Add(n, cm, ts, st)
				}
			}
		}
	}
	f.Fuzz(func(t *testing.T, seed int64, colorMode uint8, timestamps bool, stackTraces bool) {
		var cm ColorMode
		switch colorMode % 3 {
		case 0:
			cm = "never"
		case 1:
			cm = "always"
		case 2:
			cm = "auto"
		default:
			panic("unreachable")
		}

		pr := protorand.New()
		pr.Seed(seed)
		ev := &tetragon.GetEventsResponse{}
		msg, err := pr.Gen(ev)
		require.NoError(t, err)

		if helpers.ResponseGetProcess(msg.(*tetragon.GetEventsResponse)) == nil {
			t.Skipf("Empty process")
		}

		var buf1 bytes.Buffer
		compactEncoder := NewCompactEncoder(&buf1, cm, timestamps, stackTraces, false)
		err = compactEncoder.Encode(msg)
		require.NoError(t, err)
	})
}
