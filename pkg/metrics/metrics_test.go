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

	"github.com/isovalent/tetragon-oss/pkg/api"
	"github.com/isovalent/tetragon-oss/pkg/api/processapi"

	"github.com/isovalent/tetragon-oss/api/v1/fgs"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

func Test_handleProcessedEvent(t *testing.T) {
	assert.NoError(t, testutil.CollectAndCompare(EventsProcessed, strings.NewReader("")))
	handleProcessedEvent(nil)
	// empty process
	handleProcessedEvent(&fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessKprobe{ProcessKprobe: &fgs.ProcessKprobe{}}})
	handleProcessedEvent(&fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessExec{ProcessExec: &fgs.ProcessExec{}}})
	handleProcessedEvent(&fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessTracepoint{ProcessTracepoint: &fgs.ProcessTracepoint{}}})
	handleProcessedEvent(&fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessDns{ProcessDns: &fgs.ProcessDns{}}})
	handleProcessedEvent(&fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessExit{ProcessExit: &fgs.ProcessExit{}}})

	// empty pod
	handleProcessedEvent(&fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessKprobe{ProcessKprobe: &fgs.ProcessKprobe{
		Process: &fgs.Process{Binary: "binary_a"},
	}}})
	handleProcessedEvent(&fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessExec{ProcessExec: &fgs.ProcessExec{
		Process: &fgs.Process{Binary: "binary_b"},
	}}})
	handleProcessedEvent(&fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessTracepoint{ProcessTracepoint: &fgs.ProcessTracepoint{
		Process: &fgs.Process{Binary: "binary_c"},
	}}})
	handleProcessedEvent(&fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessDns{ProcessDns: &fgs.ProcessDns{
		Process: &fgs.Process{Binary: "binary_d"},
	}}})
	handleProcessedEvent(&fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessExit{ProcessExit: &fgs.ProcessExit{
		Process: &fgs.Process{Binary: "binary_e"},
	}}})

	// with pod
	handleProcessedEvent(&fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessKprobe{ProcessKprobe: &fgs.ProcessKprobe{
		Process: &fgs.Process{
			Binary: "binary_a",
			Pod:    &fgs.Pod{Namespace: "namespace_a", Name: "pod_a"},
		},
	}}})
	handleProcessedEvent(&fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessExec{ProcessExec: &fgs.ProcessExec{
		Process: &fgs.Process{
			Binary: "binary_b",
			Pod:    &fgs.Pod{Namespace: "namespace_b", Name: "pod_b"},
		},
	}}})
	handleProcessedEvent(&fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessTracepoint{ProcessTracepoint: &fgs.ProcessTracepoint{
		Process: &fgs.Process{
			Binary: "binary_c",
			Pod:    &fgs.Pod{Namespace: "namespace_c", Name: "pod_c"},
		},
	}}})
	handleProcessedEvent(&fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessDns{ProcessDns: &fgs.ProcessDns{
		Process: &fgs.Process{
			Binary: "binary_d",
			Pod:    &fgs.Pod{Namespace: "namespace_d", Name: "pod_d"},
		},
	}}})
	handleProcessedEvent(&fgs.GetEventsResponse{Event: &fgs.GetEventsResponse_ProcessExit{ProcessExit: &fgs.ProcessExit{
		Process: &fgs.Process{
			Binary: "binary_e",
			Pod:    &fgs.Pod{Namespace: "namespace_e", Name: "pod_e"},
		},
	}}})

	expected := strings.NewReader(`# HELP isovalent_events_total The total number of FGS events
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
	expected := strings.NewReader(`# HELP isovalent_flags_total The total number of FGS flags. For internal use only.
# TYPE isovalent_flags_total counter
isovalent_flags_total{type="clone"} 1
isovalent_flags_total{type="execve"} 1
`)
	assert.NoError(t, testutil.CollectAndCompare(FlagCount, expected))
}
