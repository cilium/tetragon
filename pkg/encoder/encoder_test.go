// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package encoder

import (
	"bytes"
	"os"
	"testing"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/stretchr/testify/assert"
)

func TestCompactEncoder_InvalidEventToString(t *testing.T) {
	p := NewCompactEncoder(os.Stdout, Never, false)

	// should fail if the event field is nil.
	_, err := p.eventToString(&tetragon.GetEventsResponse{})
	assert.Error(t, err)
}

func TestCompactEncoder_ExecEventToString(t *testing.T) {
	p := NewCompactEncoder(os.Stdout, Never, false)

	// should fail if the process field is nil.
	_, err := p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExec{
			ProcessExec: &tetragon.ProcessExec{},
		},
	})
	assert.Error(t, err)

	// without pod info
	result, err := p.eventToString(&tetragon.GetEventsResponse{
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
	assert.NoError(t, err)
	assert.Equal(t, "🚀 process my-node /usr/bin/curl cilium.io", result)

	// with pod info
	result, err = p.eventToString(&tetragon.GetEventsResponse{
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
	assert.NoError(t, err)
	assert.Equal(t, "🚀 process kube-system/tetragon /usr/bin/curl cilium.io", result)
}

func TestCompactEncoder_ExitEventToString(t *testing.T) {
	p := NewCompactEncoder(os.Stdout, Never, false)

	// should fail if the process field is nil.
	_, err := p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExit{
			ProcessExit: &tetragon.ProcessExit{},
		},
	})
	assert.Error(t, err)

	// with status
	result, err := p.eventToString(&tetragon.GetEventsResponse{
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
	assert.NoError(t, err)
	assert.Equal(t, "💥 exit    kube-system/tetragon /usr/bin/curl cilium.io 1", result)

	// with signal
	result, err = p.eventToString(&tetragon.GetEventsResponse{
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
	assert.NoError(t, err)
	assert.Equal(t, "💥 exit    kube-system/tetragon /usr/bin/curl cilium.io SIGKILL", result)
}

func TestCompactEncoder_KprobeEventToString(t *testing.T) {
	p := NewCompactEncoder(os.Stdout, Never, false)

	// should fail without process field
	_, err := p.eventToString(&tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &tetragon.ProcessKprobe{
				FunctionName: "unhandled_function",
			},
		},
	})
	assert.Error(t, err)

	// unknown function
	result, err := p.eventToString(&tetragon.GetEventsResponse{
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
	assert.NoError(t, err)
	assert.Equal(t, "⁉️ syscall kube-system/tetragon /usr/bin/curl unhandled_function", result)
}

func TestCompactEncoder_KprobeOpenEventToString(t *testing.T) {
	p := NewCompactEncoder(os.Stdout, Never, false)

	// open without args
	result, err := p.eventToString(&tetragon.GetEventsResponse{
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
	assert.NoError(t, err)
	assert.Equal(t, "📬 open    kube-system/tetragon /usr/bin/curl ", result)

	// open with args
	result, err = p.eventToString(&tetragon.GetEventsResponse{
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
	assert.NoError(t, err)
	assert.Equal(t, "📬 open    kube-system/tetragon /usr/bin/curl /etc/password", result)
}

func TestCompactEncoder_KprobeWriteEventToString(t *testing.T) {
	p := NewCompactEncoder(os.Stdout, Never, false)

	// write without args
	result, err := p.eventToString(&tetragon.GetEventsResponse{
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
	assert.NoError(t, err)
	assert.Equal(t, "📝 write   kube-system/tetragon /usr/bin/curl  ", result)

	// write with args
	result, err = p.eventToString(&tetragon.GetEventsResponse{
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
	assert.NoError(t, err)
	assert.Equal(t, "📝 write   kube-system/tetragon /usr/bin/curl /etc/password 1234 bytes", result)
}

func TestCompactEncoder_KprobeCloseEventToString(t *testing.T) {
	p := NewCompactEncoder(os.Stdout, Never, false)

	// open without args
	result, err := p.eventToString(&tetragon.GetEventsResponse{
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
	assert.NoError(t, err)
	assert.Equal(t, "📪 close   kube-system/tetragon /usr/bin/curl ", result)

	// open with args
	result, err = p.eventToString(&tetragon.GetEventsResponse{
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
	assert.NoError(t, err)
	assert.Equal(t, "📪 close   kube-system/tetragon /usr/bin/curl /etc/password", result)
}

func TestCompactEncoder_Encode(t *testing.T) {
	var b bytes.Buffer
	p := NewCompactEncoder(&b, Never, false)

	// invalid event
	err := p.Encode(nil)
	assert.Error(t, err)

	// more invalid event
	err = p.Encode(&tetragon.GetEventsResponse{})
	assert.Error(t, err)

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
	assert.NoError(t, err)
	assert.Equal(t, "🚀 process kube-system/tetragon /usr/bin/curl cilium.io\n", b.String())
}

func TestCompactEncoder_EncodeWithTimestamp(t *testing.T) {
	var b bytes.Buffer
	p := NewCompactEncoder(&b, Never, true)

	// invalid event
	err := p.Encode(nil)
	assert.Error(t, err)

	// more invalid event
	err = p.Encode(&tetragon.GetEventsResponse{})
	assert.Error(t, err)

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
	assert.NoError(t, err)
	assert.Equal(t, "1970-01-01T00:00:00.000000000Z 🚀 process kube-system/tetragon /usr/bin/curl cilium.io\n", b.String())
}
