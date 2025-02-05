// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package filters

import (
	"context"
	"os"
	"testing"

	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestMain(m *testing.M) {
	// Needed for cap filters
	option.Config.EnableProcessCred = true
	option.Config.EnableProcessAncestors = true

	code := m.Run()
	os.Exit(code)
}

func TestParseFilterList(t *testing.T) {
	f := `{"namespace":["kube-system",""]}
{"health_check":true}
{"binary_regex":["kube.*","iptables"]}
{"binary_regex":["/usr/sbin/.*"],"namespace":["default"]}
{"pid_set":[1]}
{"event_set":["PROCESS_EXEC", "PROCESS_EXIT", "PROCESS_KPROBE", "PROCESS_TRACEPOINT"]}
{"arguments_regex":["^--version$","^-a -b -c$"]}
{"capabilities": {"effective": {"all": ["CAP_BPF", "CAP_SYS_ADMIN"]}}}
{"cel_expression": ["process_exec.process.bad_field_name == 'curl'"]}`
	filterProto, err := ParseFilterList(f, true)
	assert.NoError(t, err)
	if diff := cmp.Diff(
		[]*tetragon.Filter{
			{Namespace: []string{"kube-system", ""}},
			{HealthCheck: &wrapperspb.BoolValue{Value: true}},
			{BinaryRegex: []string{"kube.*", "iptables"}},
			{BinaryRegex: []string{"/usr/sbin/.*"}, Namespace: []string{"default"}},
			{PidSet: []uint32{1}},
			{EventSet: []tetragon.EventType{tetragon.EventType_PROCESS_EXEC, tetragon.EventType_PROCESS_EXIT, tetragon.EventType_PROCESS_KPROBE, tetragon.EventType_PROCESS_TRACEPOINT}},
			{ArgumentsRegex: []string{"^--version$", "^-a -b -c$"}},
			{Capabilities: &tetragon.CapFilter{
				Effective: &tetragon.CapFilterSet{
					All: []tetragon.CapabilitiesType{tetragon.CapabilitiesType_CAP_BPF, tetragon.CapabilitiesType_CAP_SYS_ADMIN},
				},
			}},
			{CelExpression: []string{"process_exec.process.bad_field_name == 'curl'"}},
		},
		filterProto,
		cmpopts.IgnoreUnexported(tetragon.Filter{}),
		cmpopts.IgnoreUnexported(tetragon.CapFilter{}),
		cmpopts.IgnoreUnexported(tetragon.CapFilterSet{}),
		cmpopts.IgnoreUnexported(wrapperspb.BoolValue{}),
	); diff != "" {
		t.Errorf("filter mismatch (-want +got):\n%s", diff)
	}
	_, err = ParseFilterList("invalid filter json", true)
	assert.Error(t, err)
	filterProto, err = ParseFilterList("", true)
	assert.NoError(t, err)
	assert.Empty(t, filterProto)
	filterProto, err = ParseFilterList(`{"pid_set":[1]}`, false)
	assert.Error(t, err)
	assert.Empty(t, filterProto)
}

func TestEventTypeFilterMatch(t *testing.T) {
	f := []*tetragon.Filter{{
		EventSet: []tetragon.EventType{
			tetragon.EventType_PROCESS_EXEC,
		},
	}}

	fl, err := BuildFilterList(context.Background(), f, []OnBuildFilter{&EventTypeFilter{}})
	assert.NoError(t, err)
	ev := v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{Process: &tetragon.Process{Pod: &tetragon.Pod{Namespace: "kube-system"}}},
			},
		},
	}
	assert.True(t, fl.MatchOne(&ev))
}

func TestEventTypeFilterNoMatch(t *testing.T) {
	f := []*tetragon.Filter{{
		EventSet: []tetragon.EventType{
			tetragon.EventType_PROCESS_EXIT,
		},
	}}

	fl, err := BuildFilterList(context.Background(), f, []OnBuildFilter{&EventTypeFilter{}})
	assert.NoError(t, err)
	ev := v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{Process: &tetragon.Process{Pod: &tetragon.Pod{Namespace: "kube-system"}}},
			},
		},
	}
	assert.False(t, fl.MatchOne(&ev))
}
