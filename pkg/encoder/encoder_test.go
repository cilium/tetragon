// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package encoder

import (
	"bytes"
	"os"
	"testing"

	"github.com/cilium/tetragon/api/v1/fgs"
	"github.com/stretchr/testify/assert"
)

func TestCompactEncoder_InvalidEventToString(t *testing.T) {
	p := NewCompactEncoder(os.Stdout, Never)

	// should fail if the event field is nil.
	_, err := p.eventToString(&fgs.GetEventsResponse{})
	assert.Error(t, err)
}

func TestCompactEncoder_ExecEventToString(t *testing.T) {
	p := NewCompactEncoder(os.Stdout, Never)

	// should fail if the process field is nil.
	_, err := p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessExec{
			ProcessExec: &fgs.ProcessExec{},
		},
	})
	assert.Error(t, err)

	// without pod info
	result, err := p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessExec{
			ProcessExec: &fgs.ProcessExec{
				Process: &fgs.Process{
					Binary:    "/usr/bin/curl",
					Arguments: "isovalent.com",
				},
			},
		},
		NodeName: "my-node",
	})
	assert.NoError(t, err)
	assert.Equal(t, "🚀 process my-node /usr/bin/curl isovalent.com", result)

	// with pod info
	result, err = p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessExec{
			ProcessExec: &fgs.ProcessExec{
				Process: &fgs.Process{
					Binary:    "/usr/bin/curl",
					Arguments: "isovalent.com",
					Pod: &fgs.Pod{
						Namespace: "kube-system",
						Name:      "hubble-enterprise",
					},
				},
			},
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, "🚀 process kube-system/hubble-enterprise /usr/bin/curl isovalent.com", result)
}

func TestCompactEncoder_DnsEventToString(t *testing.T) {
	p := NewCompactEncoder(os.Stdout, Never)

	// should fail if the process field is nil.
	_, err := p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessDns{
			ProcessDns: &fgs.ProcessDns{},
		},
	})
	assert.Error(t, err)

	// should fail if dns field is nil
	_, err = p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessDns{
			ProcessDns: &fgs.ProcessDns{
				Process: &fgs.Process{
					Binary: "/usr/bin/curl",
				},
			},
		},
		NodeName: "my-node",
	})
	assert.Error(t, err)

	// with dns info.
	result, err := p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessDns{
			ProcessDns: &fgs.ProcessDns{
				Process: &fgs.Process{
					Binary: "/usr/bin/curl",
				},
				Dns: &fgs.DnsInfo{
					Names: []string{"isovalent.com"},
					Ips:   []string{"1.2.3.4"},
				},
			},
		},
		NodeName: "my-node",
	})
	assert.NoError(t, err)
	assert.Equal(t, "📖 dns     my-node /usr/bin/curl [isovalent.com] => [1.2.3.4]", result)
}

func TestCompactEncoder_ExitEventToString(t *testing.T) {
	p := NewCompactEncoder(os.Stdout, Never)

	// should fail if the process field is nil.
	_, err := p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessExit{
			ProcessExit: &fgs.ProcessExit{},
		},
	})
	assert.Error(t, err)

	// with status
	result, err := p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessExit{
			ProcessExit: &fgs.ProcessExit{
				Process: &fgs.Process{
					Binary:    "/usr/bin/curl",
					Arguments: "isovalent.com",
					Pod: &fgs.Pod{
						Namespace: "kube-system",
						Name:      "hubble-enterprise",
					},
				},
				Status: 1,
			},
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, "💥 exit    kube-system/hubble-enterprise /usr/bin/curl isovalent.com 1", result)

	// with signal
	result, err = p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessExit{
			ProcessExit: &fgs.ProcessExit{
				Process: &fgs.Process{
					Binary:    "/usr/bin/curl",
					Arguments: "isovalent.com",
					Pod: &fgs.Pod{
						Namespace: "kube-system",
						Name:      "hubble-enterprise",
					},
				},
				Signal: "SIGKILL",
			},
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, "💥 exit    kube-system/hubble-enterprise /usr/bin/curl isovalent.com SIGKILL", result)
}

func TestCompactEncoder_KprobeEventToString(t *testing.T) {
	p := NewCompactEncoder(os.Stdout, Never)

	// should fail without process field
	_, err := p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &fgs.ProcessKprobe{
				FunctionName: "unhandled_function",
			},
		},
	})
	assert.Error(t, err)

	// unknown function
	result, err := p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &fgs.ProcessKprobe{
				Process: &fgs.Process{
					Binary: "/usr/bin/curl",
					Pod: &fgs.Pod{
						Namespace: "kube-system",
						Name:      "hubble-enterprise",
					},
				},
				FunctionName: "unhandled_function",
			},
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, "⁉️ syscall kube-system/hubble-enterprise /usr/bin/curl unhandled_function", result)
}

func TestCompactEncoder_KprobeOpenEventToString(t *testing.T) {
	p := NewCompactEncoder(os.Stdout, Never)

	// open without args
	result, err := p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &fgs.ProcessKprobe{
				Process: &fgs.Process{
					Binary: "/usr/bin/curl",
					Pod: &fgs.Pod{
						Namespace: "kube-system",
						Name:      "hubble-enterprise",
					},
				},
				FunctionName: "fd_install",
			},
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, "📬 open    kube-system/hubble-enterprise /usr/bin/curl ", result)

	// open with args
	result, err = p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &fgs.ProcessKprobe{
				Process: &fgs.Process{
					Binary: "/usr/bin/curl",
					Pod: &fgs.Pod{
						Namespace: "kube-system",
						Name:      "hubble-enterprise",
					},
				},
				FunctionName: "fd_install",
				Args: []*fgs.KprobeArgument{
					nil,
					{Arg: &fgs.KprobeArgument_FileArg{FileArg: &fgs.KprobeFile{Path: "/etc/password"}}},
				},
			},
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, "📬 open    kube-system/hubble-enterprise /usr/bin/curl /etc/password", result)
}

func TestCompactEncoder_KprobeWriteEventToString(t *testing.T) {
	p := NewCompactEncoder(os.Stdout, Never)

	// write without args
	result, err := p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &fgs.ProcessKprobe{
				Process: &fgs.Process{
					Binary: "/usr/bin/curl",
					Pod: &fgs.Pod{
						Namespace: "kube-system",
						Name:      "hubble-enterprise",
					},
				},
				FunctionName: "__x64_sys_write",
			},
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, "📝 write   kube-system/hubble-enterprise /usr/bin/curl  ", result)

	// write with args
	result, err = p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &fgs.ProcessKprobe{
				Process: &fgs.Process{
					Binary: "/usr/bin/curl",
					Pod: &fgs.Pod{
						Namespace: "kube-system",
						Name:      "hubble-enterprise",
					},
				},
				FunctionName: "__x64_sys_write",
				Args: []*fgs.KprobeArgument{
					{Arg: &fgs.KprobeArgument_FileArg{FileArg: &fgs.KprobeFile{Path: "/etc/password"}}},
					nil,
					{Arg: &fgs.KprobeArgument_SizeArg{SizeArg: 1234}},
				},
			},
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, "📝 write   kube-system/hubble-enterprise /usr/bin/curl /etc/password 1234 bytes", result)
}

func TestCompactEncoder_KprobeCloseEventToString(t *testing.T) {
	p := NewCompactEncoder(os.Stdout, Never)

	// open without args
	result, err := p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &fgs.ProcessKprobe{
				Process: &fgs.Process{
					Binary: "/usr/bin/curl",
					Pod: &fgs.Pod{
						Namespace: "kube-system",
						Name:      "hubble-enterprise",
					},
				},
				FunctionName: "__x64_sys_close",
			},
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, "📪 close   kube-system/hubble-enterprise /usr/bin/curl ", result)

	// open with args
	result, err = p.eventToString(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &fgs.ProcessKprobe{
				Process: &fgs.Process{
					Binary: "/usr/bin/curl",
					Pod: &fgs.Pod{
						Namespace: "kube-system",
						Name:      "hubble-enterprise",
					},
				},
				FunctionName: "__x64_sys_close",
				Args: []*fgs.KprobeArgument{
					{Arg: &fgs.KprobeArgument_FileArg{FileArg: &fgs.KprobeFile{Path: "/etc/password"}}},
				},
			},
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, "📪 close   kube-system/hubble-enterprise /usr/bin/curl /etc/password", result)
}

func TestCompactEncoder_Encode(t *testing.T) {
	var b bytes.Buffer
	p := NewCompactEncoder(&b, Never)

	// invalid event
	err := p.Encode(nil)
	assert.Error(t, err)

	// more invalid event
	err = p.Encode(&fgs.GetEventsResponse{})
	assert.Error(t, err)

	// valid event
	err = p.Encode(&fgs.GetEventsResponse{
		Event: &fgs.GetEventsResponse_ProcessExec{
			ProcessExec: &fgs.ProcessExec{
				Process: &fgs.Process{
					Binary:    "/usr/bin/curl",
					Arguments: "isovalent.com",
					Pod: &fgs.Pod{
						Namespace: "kube-system",
						Name:      "hubble-enterprise",
					},
				},
			},
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, "🚀 process kube-system/hubble-enterprise /usr/bin/curl isovalent.com\n", b.String())
}
