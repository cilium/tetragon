// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package filters

import (
	"testing"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/stretchr/testify/assert"
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
						Labels: []string{
							"foo",
							"bar",
							"qux",
							"baz",
						},
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
						"process",
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
	filters := FieldFiltersFromGetEventsRequest(request)
	for _, filter := range filters {
		filter.Filter(ev)
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

	filter := NewExcludeFieldFilter([]tetragon.EventType{tetragon.EventType_PROCESS_EXIT}, []string{"process.pid"})
	filter.Filter(ev)

	assert.NotEmpty(t, ev.GetProcessExec().Process.Pid)

	filter = NewExcludeFieldFilter([]tetragon.EventType{tetragon.EventType_PROCESS_EXEC}, []string{"process.pid"})
	filter.Filter(ev)

	assert.Empty(t, ev.GetProcessExec().Process.Pid)
}

func TestEmptyFieldFilter(t *testing.T) {
	filter := NewIncludeFieldFilter([]tetragon.EventType{}, []string{})

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
						Labels: []string{
							"foo",
							"bar",
							"qux",
							"baz",
						},
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
						Labels: []string{
							"foo",
							"bar",
							"qux",
							"baz",
						},
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
	filter.Filter(ev)
	assert.True(t, proto.Equal(ev, expected), "events are equal after filter")
}
