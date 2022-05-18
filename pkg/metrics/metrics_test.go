// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package metrics

import (
	"strings"
	"testing"

	"github.com/cilium/tetragon/pkg/api"
	"github.com/cilium/tetragon/pkg/api/processapi"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

func Test_handleProcessedEvent(t *testing.T) {
	assert.NoError(t, testutil.CollectAndCompare(EventsProcessed, strings.NewReader("")))
	handleProcessedEvent(nil)
	// empty process
	handleProcessedEvent(&tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessKprobe{ProcessKprobe: &tetragon.ProcessKprobe{}}})
	handleProcessedEvent(&tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessExec{ProcessExec: &tetragon.ProcessExec{}}})
	handleProcessedEvent(&tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessTracepoint{ProcessTracepoint: &tetragon.ProcessTracepoint{}}})
	handleProcessedEvent(&tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessDns{ProcessDns: &tetragon.ProcessDns{}}})
	handleProcessedEvent(&tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessExit{ProcessExit: &tetragon.ProcessExit{}}})

	// empty pod
	handleProcessedEvent(&tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessKprobe{ProcessKprobe: &tetragon.ProcessKprobe{
		Process: &tetragon.Process{Binary: "binary_a"},
	}}})
	handleProcessedEvent(&tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessExec{ProcessExec: &tetragon.ProcessExec{
		Process: &tetragon.Process{Binary: "binary_b"},
	}}})
	handleProcessedEvent(&tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessTracepoint{ProcessTracepoint: &tetragon.ProcessTracepoint{
		Process: &tetragon.Process{Binary: "binary_c"},
	}}})
	handleProcessedEvent(&tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessDns{ProcessDns: &tetragon.ProcessDns{
		Process: &tetragon.Process{Binary: "binary_d"},
	}}})
	handleProcessedEvent(&tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessExit{ProcessExit: &tetragon.ProcessExit{
		Process: &tetragon.Process{Binary: "binary_e"},
	}}})

	// with pod
	handleProcessedEvent(&tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessKprobe{ProcessKprobe: &tetragon.ProcessKprobe{
		Process: &tetragon.Process{
			Binary: "binary_a",
			Pod:    &tetragon.Pod{Namespace: "namespace_a", Name: "pod_a"},
		},
	}}})
	handleProcessedEvent(&tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessExec{ProcessExec: &tetragon.ProcessExec{
		Process: &tetragon.Process{
			Binary: "binary_b",
			Pod:    &tetragon.Pod{Namespace: "namespace_b", Name: "pod_b"},
		},
	}}})
	handleProcessedEvent(&tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessTracepoint{ProcessTracepoint: &tetragon.ProcessTracepoint{
		Process: &tetragon.Process{
			Binary: "binary_c",
			Pod:    &tetragon.Pod{Namespace: "namespace_c", Name: "pod_c"},
		},
	}}})
	handleProcessedEvent(&tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessDns{ProcessDns: &tetragon.ProcessDns{
		Process: &tetragon.Process{
			Binary: "binary_d",
			Pod:    &tetragon.Pod{Namespace: "namespace_d", Name: "pod_d"},
		},
	}}})
	handleProcessedEvent(&tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessExit{ProcessExit: &tetragon.ProcessExit{
		Process: &tetragon.Process{
			Binary: "binary_e",
			Pod:    &tetragon.Pod{Namespace: "namespace_e", Name: "pod_e"},
		},
	}}})

	expected := strings.NewReader(`# HELP isovalent_events_total The total number of Tetragon events
# TYPE isovalent_events_total counter
isovalent_events_total{binary="",namespace="",pod="",type="PROCESS_KPROBE"} 1
isovalent_events_total{binary="",namespace="",pod="",type="PROCESS_EXEC"} 1
isovalent_events_total{binary="",namespace="",pod="",type="PROCESS_EXIT"} 1
isovalent_events_total{binary="",namespace="",pod="",type="PROCESS_TRACEPOINT"} 1
isovalent_events_total{binary="",namespace="",pod="",type="PROCESS_DNS"} 1
isovalent_events_total{binary="",namespace="",pod="",type="unknown"} 1
isovalent_events_total{binary="binary_a",namespace="",pod="",type="PROCESS_KPROBE"} 1
isovalent_events_total{binary="binary_a",namespace="namespace_a",pod="pod_a",type="PROCESS_KPROBE"} 1
isovalent_events_total{binary="binary_b",namespace="",pod="",type="PROCESS_EXEC"} 1
isovalent_events_total{binary="binary_b",namespace="namespace_b",pod="pod_b",type="PROCESS_EXEC"} 1
isovalent_events_total{binary="binary_c",namespace="",pod="",type="PROCESS_TRACEPOINT"} 1
isovalent_events_total{binary="binary_c",namespace="namespace_c",pod="pod_c",type="PROCESS_TRACEPOINT"} 1
isovalent_events_total{binary="binary_d",namespace="",pod="",type="PROCESS_DNS"} 1
isovalent_events_total{binary="binary_d",namespace="namespace_d",pod="pod_d",type="PROCESS_DNS"} 1
isovalent_events_total{binary="binary_e",namespace="",pod="",type="PROCESS_EXIT"} 1
isovalent_events_total{binary="binary_e",namespace="namespace_e",pod="pod_e",type="PROCESS_EXIT"} 1
`)
	assert.NoError(t, testutil.CollectAndCompare(EventsProcessed, expected))
}

func Test_handleOriginalEvent(t *testing.T) {
	handleOriginalEvent(nil)
	handleOriginalEvent(&processapi.MsgExecveEventUnix{})
	assert.NoError(t, testutil.CollectAndCompare(FlagCount, strings.NewReader("")))
	handleOriginalEvent(&processapi.MsgExecveEventUnix{
		Process: processapi.MsgProcess{
			Flags: api.EventClone | api.EventExecve,
		},
	})
	expected := strings.NewReader(`# HELP isovalent_flags_total The total number of Tetragon flags. For internal use only.
# TYPE isovalent_flags_total counter
isovalent_flags_total{type="clone"} 1
isovalent_flags_total{type="execve"} 1
`)
	assert.NoError(t, testutil.CollectAndCompare(FlagCount, expected))
}
