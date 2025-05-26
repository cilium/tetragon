// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package fieldfilters

import (
	"fmt"
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestEventFieldFilters(t *testing.T) {
	ev := &tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExec{
			ProcessExec: &tetragon.ProcessExec{
				Process: &tetragon.Process{
					Pid: wrapperspb.UInt32(1337),
					Uid: wrapperspb.UInt32(0xdeadbeef),
					StartTime: &timestamppb.Timestamp{
						Seconds: 1000,
						Nanos:   1000,
					},
					Pod: &tetragon.Pod{
						Namespace: "kube-system",
						Name:      "foobar",
						Container: &tetragon.Container{
							Id:   "testificate",
							Name: "testificate",
							Image: &tetragon.Image{
								Id:   "testificate",
								Name: "testificate",
							},
							StartTime: &timestamppb.Timestamp{
								Seconds: 1000,
								Nanos:   1000,
							},
							Pid:            wrapperspb.UInt32(1),
							MaybeExecProbe: false,
						},
						PodLabels: map[string]string{
							"test": "test",
						},
					},
				},
				Parent: &tetragon.Process{},
			},
		},
	}

	request := &tetragon.GetEventsRequest{
		AllowList:          []*tetragon.Filter{},
		DenyList:           []*tetragon.Filter{},
		AggregationOptions: &tetragon.AggregationOptions{},
		FieldFilters: []*tetragon.FieldFilter{
			{
				EventSet: []tetragon.EventType{},
				Fields: &fieldmaskpb.FieldMask{
					Paths: []string{
						"parent",
						"process.pid",
						"process.uid",
						"process.pod",
					},
				},
				Action: tetragon.FieldFilterAction_INCLUDE,
			},
			{
				EventSet: []tetragon.EventType{},
				Fields: &fieldmaskpb.FieldMask{
					Paths: []string{
						"process.pid",
						"process.pod.pod_labels",
						"process.pod.container.image",
						"process.pod.namespace",
					},
				},
				Action: tetragon.FieldFilterAction_EXCLUDE,
			},
		},
	}

	// Construct the filter
	filters, err := FieldFiltersFromGetEventsRequest(request)
	require.NoError(t, err)
	for _, filter := range filters {
		ev, err = filter.Filter(ev)
		require.NoError(t, err)
	}

	// These fields should all have been included and so should not be empty
	assert.NotEmpty(t, ev.GetProcessExec())
	assert.NotEmpty(t, ev.GetProcessExec().Process.Uid)
	assert.NotEmpty(t, ev.GetProcessExec().Process)
	assert.NotEmpty(t, ev.GetProcessExec().Process.Pod)
	assert.NotEmpty(t, ev.GetProcessExec().Process.Pod.Name)
	assert.NotEmpty(t, ev.GetProcessExec().Process.Pod.Container)

	// These fields should have been excluded and so should be empty
	assert.Empty(t, ev.GetProcessExec().Parent)
	assert.Empty(t, ev.GetProcessExec().Process.Pid)
	assert.Empty(t, ev.GetProcessExec().Process.Pod.PodLabels)
	assert.Empty(t, ev.GetProcessExec().Process.Pod.Container.Image)
	assert.Empty(t, ev.GetProcessExec().Process.Pod.Namespace)
}

func TestFieldFilterByEventType(t *testing.T) {
	ev := &tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExec{
			ProcessExec: &tetragon.ProcessExec{
				Process: &tetragon.Process{
					Pid: wrapperspb.UInt32(1337),
				},
			},
		},
	}

	filter, err := NewExcludeFieldFilter([]tetragon.EventType{tetragon.EventType_PROCESS_EXIT}, []string{"process.pid"}, false)
	require.NoError(t, err)
	ev, _ = filter.Filter(ev)

	assert.NotEmpty(t, ev.GetProcessExec().Process.Pid)

	filter, err = NewExcludeFieldFilter([]tetragon.EventType{tetragon.EventType_PROCESS_EXEC}, []string{"process.pid"}, false)
	require.NoError(t, err)
	ev, _ = filter.Filter(ev)

	assert.Empty(t, ev.GetProcessExec().Process.Pid)
}

func TestEmptyFieldFilter(t *testing.T) {
	filter, err := NewIncludeFieldFilter([]tetragon.EventType{}, []string{}, false)
	require.NoError(t, err)

	ev := &tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExec{
			ProcessExec: &tetragon.ProcessExec{
				Process: &tetragon.Process{
					Pid: wrapperspb.UInt32(1337),
					Uid: wrapperspb.UInt32(0xdeadbeef),
					StartTime: &timestamppb.Timestamp{
						Seconds: 1000,
						Nanos:   1000,
					},
					Pod: &tetragon.Pod{
						Namespace: "kube-system",
						Name:      "foobar",
						Container: &tetragon.Container{
							Id:   "testificate",
							Name: "testificate",
							Image: &tetragon.Image{
								Id:   "testificate",
								Name: "testificate",
							},
							StartTime: &timestamppb.Timestamp{
								Seconds: 1000,
								Nanos:   1000,
							},
							Pid:            wrapperspb.UInt32(1),
							MaybeExecProbe: false,
						},
						PodLabels: map[string]string{
							"test": "test",
						},
					},
				},
				Parent: &tetragon.Process{},
			},
		},
	}

	expected := &tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExec{
			ProcessExec: &tetragon.ProcessExec{
				Process: &tetragon.Process{
					Pid: wrapperspb.UInt32(1337),
					Uid: wrapperspb.UInt32(0xdeadbeef),
					StartTime: &timestamppb.Timestamp{
						Seconds: 1000,
						Nanos:   1000,
					},
					Pod: &tetragon.Pod{
						Namespace: "kube-system",
						Name:      "foobar",
						Container: &tetragon.Container{
							Id:   "testificate",
							Name: "testificate",
							Image: &tetragon.Image{
								Id:   "testificate",
								Name: "testificate",
							},
							StartTime: &timestamppb.Timestamp{
								Seconds: 1000,
								Nanos:   1000,
							},
							Pid:            wrapperspb.UInt32(1),
							MaybeExecProbe: false,
						},
						PodLabels: map[string]string{
							"test": "test",
						},
					},
				},
				Parent: &tetragon.Process{},
			},
		},
	}

	assert.True(t, proto.Equal(ev, expected), "events are equal before filter")
	ev, _ = filter.Filter(ev)
	assert.True(t, proto.Equal(ev, expected), "events are equal after filter")
}

func TestEmptyFieldFilterTopLevelInformation(t *testing.T) {
	ev := &tetragon.GetEventsResponse{
		NodeName: "foobarqux",
		AggregationInfo: &tetragon.AggregationInfo{
			Count: 1000,
		},
		Time: &timestamppb.Timestamp{
			Seconds: 1000,
			Nanos:   1000,
		},
		Event: &tetragon.GetEventsResponse_ProcessExec{
			ProcessExec: &tetragon.ProcessExec{
				Process: &tetragon.Process{},
				Parent:  &tetragon.Process{},
			},
		},
	}

	filter, err := NewExcludeFieldFilter(nil, nil, false)
	require.NoError(t, err)
	ev, _ = filter.Filter(ev)
	assert.NotEmpty(t, ev.NodeName, "node name must not be empty")
	assert.NotEmpty(t, ev.Time, "timestamp must not be empty")
	assert.NotEmpty(t, ev.AggregationInfo, "aggregation info must not be empty")
}

func TestFieldFilterInvertedEventSet(t *testing.T) {
	ev := &tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExec{
			ProcessExec: &tetragon.ProcessExec{
				Process: &tetragon.Process{},
				Parent:  &tetragon.Process{},
			},
		},
	}

	expected := &tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExec{
			ProcessExec: &tetragon.ProcessExec{
				Process: &tetragon.Process{},
				Parent:  &tetragon.Process{},
			},
		},
	}

	filter, err := NewExcludeFieldFilter([]tetragon.EventType{tetragon.EventType_PROCESS_EXEC}, []string{"process", "parent"}, true)
	require.NoError(t, err)
	assert.True(t, proto.Equal(ev, expected), "events are equal before filter")
	ev, _ = filter.Filter(ev)
	assert.True(t, proto.Equal(ev, expected), "events are equal after filter")

	ev = &tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExec{
			ProcessExec: &tetragon.ProcessExec{
				Process: &tetragon.Process{},
				Parent:  &tetragon.Process{},
			},
		},
	}

	expected = &tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExec{
			ProcessExec: &tetragon.ProcessExec{},
		},
	}

	filter, err = NewExcludeFieldFilter([]tetragon.EventType{tetragon.EventType_PROCESS_KPROBE}, []string{"process", "parent"}, true)
	require.NoError(t, err)
	assert.False(t, proto.Equal(ev, expected), "events are not equal before filter")
	ev, _ = filter.Filter(ev)
	assert.True(t, proto.Equal(ev, expected), "events are equal after filter")
}

func TestSlimExecEventsFieldFilterExample(t *testing.T) {
	evs := []*tetragon.GetEventsResponse{
		{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{
					Process: &tetragon.Process{
						ExecId:       "foo",
						ParentExecId: "",
						Pid: &wrapperspb.UInt32Value{
							Value: 1,
						},
						Cwd:       "/",
						Binary:    "/bin/bash",
						Arguments: "-c hello.sh",
						Flags:     "procFS",
						StartTime: &timestamppb.Timestamp{
							Seconds: 1337,
							Nanos:   100,
						},
						Auid: &wrapperspb.UInt32Value{
							Value: 2,
						},
						Pod: &tetragon.Pod{
							Namespace: "foo",
							Name:      "bar",
						},
						Docker: "qux",
						Refcnt: 12,
						Cap:    &tetragon.Capabilities{},
						Ns:     &tetragon.Namespaces{},
					},
				},
			},
		},

		{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{
					Process: &tetragon.Process{
						ExecId:       "bar",
						ParentExecId: "foo",
						Pid: &wrapperspb.UInt32Value{
							Value: 2,
						},
						Cwd:       "/",
						Binary:    "/bin/bash",
						Arguments: "-c hello.sh",
						Flags:     "procFS",
						StartTime: &timestamppb.Timestamp{
							Seconds: 1337,
							Nanos:   100,
						},
						Auid: &wrapperspb.UInt32Value{
							Value: 2,
						},
						Pod: &tetragon.Pod{
							Namespace: "foo",
							Name:      "bar",
						},
						Docker: "qux",
						Refcnt: 12,
						Cap:    &tetragon.Capabilities{},
						Ns:     &tetragon.Namespaces{},
					},
					Parent: &tetragon.Process{
						ExecId:       "foo",
						ParentExecId: "",
						Pid: &wrapperspb.UInt32Value{
							Value: 1,
						},
						Cwd:       "/",
						Binary:    "/bin/bash",
						Arguments: "-c hello.sh",
						Flags:     "procFS",
						StartTime: &timestamppb.Timestamp{
							Seconds: 1337,
							Nanos:   100,
						},
						Auid: &wrapperspb.UInt32Value{
							Value: 2,
						},
						Pod: &tetragon.Pod{
							Namespace: "foo",
							Name:      "bar",
						},
						Docker: "qux",
						Refcnt: 12,
						Cap:    &tetragon.Capabilities{},
						Ns:     &tetragon.Namespaces{},
					},
				},
			},
		},

		{
			Event: &tetragon.GetEventsResponse_ProcessKprobe{
				ProcessKprobe: &tetragon.ProcessKprobe{
					Process: &tetragon.Process{
						ExecId:       "bar",
						ParentExecId: "foo",
						Pid: &wrapperspb.UInt32Value{
							Value: 2,
						},
						Cwd:       "/",
						Binary:    "/bin/bash",
						Arguments: "-c hello.sh",
						Flags:     "procFS",
						StartTime: &timestamppb.Timestamp{
							Seconds: 1337,
							Nanos:   100,
						},
						Auid: &wrapperspb.UInt32Value{
							Value: 2,
						},
						Pod: &tetragon.Pod{
							Namespace: "foo",
							Name:      "bar",
						},
						Docker: "qux",
						Refcnt: 12,
						Cap:    &tetragon.Capabilities{},
						Ns:     &tetragon.Namespaces{},
					},
					Parent: &tetragon.Process{
						ExecId:       "foo",
						ParentExecId: "",
						Pid: &wrapperspb.UInt32Value{
							Value: 1,
						},
						Cwd:       "/",
						Binary:    "/bin/bash",
						Arguments: "-c hello.sh",
						Flags:     "procFS",
						StartTime: &timestamppb.Timestamp{
							Seconds: 1337,
							Nanos:   100,
						},
						Auid: &wrapperspb.UInt32Value{
							Value: 2,
						},
						Pod: &tetragon.Pod{
							Namespace: "foo",
							Name:      "bar",
						},
						Docker: "qux",
						Refcnt: 12,
						Cap:    &tetragon.Capabilities{},
						Ns:     &tetragon.Namespaces{},
					},
					FunctionName: "baz",
				},
			},
		},

		{
			Event: &tetragon.GetEventsResponse_ProcessExit{
				ProcessExit: &tetragon.ProcessExit{
					Process: &tetragon.Process{
						ExecId:       "bar",
						ParentExecId: "foo",
						Pid: &wrapperspb.UInt32Value{
							Value: 2,
						},
						Cwd:       "/",
						Binary:    "/bin/bash",
						Arguments: "-c hello.sh",
						Flags:     "procFS",
						StartTime: &timestamppb.Timestamp{
							Seconds: 1337,
							Nanos:   100,
						},
						Auid: &wrapperspb.UInt32Value{
							Value: 2,
						},
						Pod: &tetragon.Pod{
							Namespace: "foo",
							Name:      "bar",
						},
						Docker: "qux",
						Refcnt: 12,
						Cap:    &tetragon.Capabilities{},
						Ns:     &tetragon.Namespaces{},
					},
					Parent: &tetragon.Process{
						ExecId:       "foo",
						ParentExecId: "",
						Pid: &wrapperspb.UInt32Value{
							Value: 1,
						},
						Cwd:       "/",
						Binary:    "/bin/bash",
						Arguments: "-c hello.sh",
						Flags:     "procFS",
						StartTime: &timestamppb.Timestamp{
							Seconds: 1337,
							Nanos:   100,
						},
						Auid: &wrapperspb.UInt32Value{
							Value: 2,
						},
						Pod: &tetragon.Pod{
							Namespace: "foo",
							Name:      "bar",
						},
						Docker: "qux",
						Refcnt: 12,
						Cap:    &tetragon.Capabilities{},
						Ns:     &tetragon.Namespaces{},
					},
				},
			},
		},
	}

	expected := []*tetragon.GetEventsResponse{
		{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{
					Process: &tetragon.Process{
						ExecId:       "foo",
						ParentExecId: "",
						Pid: &wrapperspb.UInt32Value{
							Value: 1,
						},
						Cwd:       "/",
						Binary:    "/bin/bash",
						Arguments: "-c hello.sh",
						Flags:     "procFS",
						StartTime: &timestamppb.Timestamp{
							Seconds: 1337,
							Nanos:   100,
						},
						Auid: &wrapperspb.UInt32Value{
							Value: 2,
						},
						Pod: &tetragon.Pod{
							Namespace: "foo",
							Name:      "bar",
						},
						Docker: "qux",
						Refcnt: 12,
						Cap:    &tetragon.Capabilities{},
						Ns:     &tetragon.Namespaces{},
					},
				},
			},
		},

		{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{
					Process: &tetragon.Process{
						ExecId:       "bar",
						ParentExecId: "foo",
						Pid: &wrapperspb.UInt32Value{
							Value: 2,
						},
						Cwd:       "/",
						Binary:    "/bin/bash",
						Arguments: "-c hello.sh",
						Flags:     "procFS",
						StartTime: &timestamppb.Timestamp{
							Seconds: 1337,
							Nanos:   100,
						},
						Auid: &wrapperspb.UInt32Value{
							Value: 2,
						},
						Pod: &tetragon.Pod{
							Namespace: "foo",
							Name:      "bar",
						},
						Docker: "qux",
						Refcnt: 12,
						Cap:    &tetragon.Capabilities{},
						Ns:     &tetragon.Namespaces{},
					},
				},
			},
		},

		{
			Event: &tetragon.GetEventsResponse_ProcessKprobe{
				ProcessKprobe: &tetragon.ProcessKprobe{
					Process: &tetragon.Process{
						ExecId:       "bar",
						ParentExecId: "foo",
					},
					FunctionName: "baz",
				},
			},
		},

		{
			Event: &tetragon.GetEventsResponse_ProcessExit{
				ProcessExit: &tetragon.ProcessExit{
					Process: &tetragon.Process{
						ExecId:       "bar",
						ParentExecId: "foo",
					},
				},
			},
		},
	}

	ff1, err := NewExcludeFieldFilter([]tetragon.EventType{}, []string{"parent"}, false)
	require.NoError(t, err)
	ff2, err := NewExcludeFieldFilter([]tetragon.EventType{tetragon.EventType_PROCESS_EXEC}, []string{
		"process.pid",
		"process.uid",
		"process.cwd",
		"process.binary",
		"process.arguments",
		"process.flags",
		"process.start_time",
		"process.auid",
		"process.pod",
		"process.docker",
		"process.refcnt",
		"process.cap",
		"process.ns",
	}, true)
	require.NoError(t, err)

	filters := []*FieldFilter{ff1, ff2}

	for _, filter := range filters {
		for i, ev := range evs {
			ev, _ = filter.Filter(ev)
			evs[i] = ev
		}
	}
	for i := range evs {
		if !assert.True(t, proto.Equal(evs[i], expected[i]), "event %d should be equal after filter", i) {
			fmt.Println("expected: ", expected[i])
			fmt.Println("actual: ", evs[i])
		}
	}
}
