// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package eventmetrics

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api"
	"github.com/cilium/tetragon/pkg/api/processapi"
)

func TestHandleProcessedEvent(t *testing.T) {
	require.NoError(t, testutil.CollectAndCompare(EventsProcessed, strings.NewReader("")))
	handleProcessedEvent(nil, nil)
	// empty process
	handleProcessedEvent(nil, &tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessKprobe{ProcessKprobe: &tetragon.ProcessKprobe{}}})
	handleProcessedEvent(nil, &tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessExec{ProcessExec: &tetragon.ProcessExec{}}})
	handleProcessedEvent(nil, &tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessTracepoint{ProcessTracepoint: &tetragon.ProcessTracepoint{}}})
	handleProcessedEvent(nil, &tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessExit{ProcessExit: &tetragon.ProcessExit{}}})

	// empty pod
	handleProcessedEvent(nil, &tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessKprobe{ProcessKprobe: &tetragon.ProcessKprobe{
		Process: &tetragon.Process{Binary: "binary_a"},
	}}})
	handleProcessedEvent(nil, &tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessExec{ProcessExec: &tetragon.ProcessExec{
		Process: &tetragon.Process{Binary: "binary_b"},
	}}})
	handleProcessedEvent(nil, &tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessTracepoint{ProcessTracepoint: &tetragon.ProcessTracepoint{
		Process: &tetragon.Process{Binary: "binary_c"},
	}}})
	handleProcessedEvent(nil, &tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessExit{ProcessExit: &tetragon.ProcessExit{
		Process: &tetragon.Process{Binary: "binary_e"},
	}}})

	// with pod
	handleProcessedEvent(nil, &tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessKprobe{ProcessKprobe: &tetragon.ProcessKprobe{
		Process: &tetragon.Process{
			Binary: "binary_a",
			Pod:    &tetragon.Pod{Namespace: "namespace_a", Name: "pod_a", Workload: "workload_a"},
		},
	}}})
	handleProcessedEvent(nil, &tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessExec{ProcessExec: &tetragon.ProcessExec{
		Process: &tetragon.Process{
			Binary: "binary_b",
			Pod:    &tetragon.Pod{Namespace: "namespace_b", Name: "pod_b", Workload: "workload_b"},
		},
	}}})
	handleProcessedEvent(nil, &tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessTracepoint{ProcessTracepoint: &tetragon.ProcessTracepoint{
		Process: &tetragon.Process{
			Binary: "binary_c",
			Pod:    &tetragon.Pod{Namespace: "namespace_c", Name: "pod_c", Workload: "workload_c"},
		},
	}}})
	handleProcessedEvent(nil, &tetragon.GetEventsResponse{Event: &tetragon.GetEventsResponse_ProcessExit{ProcessExit: &tetragon.ProcessExit{
		Process: &tetragon.Process{
			Binary: "binary_e",
			Pod:    &tetragon.Pod{Namespace: "namespace_e", Name: "pod_e", Workload: "workload_e"},
		},
	}}})

	// with node name
	handleProcessedEvent(nil, &tetragon.GetEventsResponse{
		NodeName: "node_a",
		Event: &tetragon.GetEventsResponse_ProcessKprobe{ProcessKprobe: &tetragon.ProcessKprobe{
			Process: &tetragon.Process{
				Binary: "binary_f",
			},
		}},
	})

	expected := strings.NewReader(`# HELP tetragon_events_total The total number of Tetragon events
# TYPE tetragon_events_total counter
tetragon_events_total{binary="",namespace="",node_name="",pod="",type="PROCESS_KPROBE",workload=""} 1
tetragon_events_total{binary="",namespace="",node_name="",pod="",type="PROCESS_EXEC",workload=""} 1
tetragon_events_total{binary="",namespace="",node_name="",pod="",type="PROCESS_EXIT",workload=""} 1
tetragon_events_total{binary="",namespace="",node_name="",pod="",type="PROCESS_TRACEPOINT",workload=""} 1
tetragon_events_total{binary="",namespace="",node_name="",pod="",type="unknown",workload=""} 1
tetragon_events_total{binary="binary_a",namespace="",node_name="",pod="",type="PROCESS_KPROBE",workload=""} 1
tetragon_events_total{binary="binary_a",namespace="namespace_a",node_name="",pod="pod_a",type="PROCESS_KPROBE",workload="workload_a"} 1
tetragon_events_total{binary="binary_b",namespace="",node_name="",pod="",type="PROCESS_EXEC",workload=""} 1
tetragon_events_total{binary="binary_b",namespace="namespace_b",node_name="",pod="pod_b",type="PROCESS_EXEC",workload="workload_b"} 1
tetragon_events_total{binary="binary_c",namespace="",node_name="",pod="",type="PROCESS_TRACEPOINT",workload=""} 1
tetragon_events_total{binary="binary_c",namespace="namespace_c",node_name="",pod="pod_c",type="PROCESS_TRACEPOINT",workload="workload_c"} 1
tetragon_events_total{binary="binary_e",namespace="",node_name="",pod="",type="PROCESS_EXIT",workload=""} 1
tetragon_events_total{binary="binary_e",namespace="namespace_e",node_name="",pod="pod_e",type="PROCESS_EXIT",workload="workload_e"} 1
tetragon_events_total{binary="binary_f",namespace="",node_name="node_a",pod="",type="PROCESS_KPROBE",workload=""} 1
`)
	require.NoError(t, testutil.CollectAndCompare(EventsProcessed, expected))
}

func TestHandleOriginalEvent(t *testing.T) {
	handleOriginalEvent(nil)
	handleOriginalEvent(&processapi.MsgExecveEventUnix{})
	require.NoError(t, testutil.CollectAndCompare(FlagCount, strings.NewReader("")))
	handleOriginalEvent(&processapi.MsgExecveEventUnix{
		Process: processapi.MsgProcess{
			Flags: api.EventClone | api.EventExecve,
		},
	})
	expected := strings.NewReader(`# HELP tetragon_flags_total The total number of Tetragon flags. For internal use only.
# TYPE tetragon_flags_total counter
tetragon_flags_total{type="clone"} 1
tetragon_flags_total{type="execve"} 1
`)
	require.NoError(t, testutil.CollectAndCompare(FlagCount, expected))
}
