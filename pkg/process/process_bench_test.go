// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package process

import (
	"fmt"
	"testing"

	"github.com/cilium/tetragon/pkg/api"
	"github.com/cilium/tetragon/pkg/api/processapi"
)

// benchSink keeps the result of the benchmarked call alive so that the
// compiler cannot optimize the allocation away.
var benchSink *ProcessInternal

func newBenchExecEvent() *processapi.MsgExecveEventUnix {
	envs := make([]string, 0, 24)
	for i := range 24 {
		envs = append(envs, fmt.Sprintf("ENV_VAR_%d=some-reasonably-long-value-%d", i, i))
	}

	return &processapi.MsgExecveEventUnix{
		Msg: processapi.MsgExecveEvent{
			Parent: processapi.MsgExecveKey{Pid: 1000, Ktime: 123456789},
			Creds: processapi.MsgGenericCred{
				Uid: 1000, Gid: 1000, Euid: 1000, Egid: 1000,
				Suid: 1000, Sgid: 1000, FSuid: 1000, FSgid: 1000,
			},
			Namespaces: processapi.MsgNamespaces{
				UtsInum: 4026531838, IpcInum: 4026531839, MntInum: 4026531841,
				PidInum: 4026531836, PidChildInum: 4026531836, NetInum: 4026531840,
				TimeInum: 4026531834, TimeChildInum: 4026531834,
				CgroupInum: 4026531835, UserInum: 4026531837,
			},
		},
		Process: processapi.MsgProcess{
			PID:      2000,
			TID:      2000,
			NSPID:    2000,
			UID:      1000,
			AUID:     1000,
			Flags:    api.EventExecve,
			Ktime:    987654321,
			Filename: "/usr/bin/bash",
			Args:     "-c echo hello world",
			Cwd:      "/home/user/work",
			Envs:     envs,
		},
	}
}

// BenchmarkInitProcessInternalExec measures the per-process cost of building a
// ProcessInternal from an exec event (excluding the process cache).
func BenchmarkInitProcessInternalExec(b *testing.B) {
	event := newBenchExecEvent()
	parent := event.Msg.Parent

	b.ReportAllocs()
	for b.Loop() {
		benchSink = initProcessInternalExec(event, parent)
	}
}
