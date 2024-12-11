// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package filters

import (
	"context"
	"testing"

	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestInvalidFilter(t *testing.T) {
	log := logrus.New()
	f := tetragon.Filter{CelExpression: []string{"process_exec.process.bad_field_name == 'curl'"}}
	celFilter := NewCELExpressionFilter(log)
	_, err := celFilter.OnBuildFilter(context.Background(), &f)
	assert.Error(t, err)
}

func TestProcessExecFilter(t *testing.T) {
	log := logrus.New()
	f := []*tetragon.Filter{{CelExpression: []string{"process_exec.process.pid > uint(1)"}}}
	fl, err := BuildFilterList(context.Background(), f, []OnBuildFilter{NewCELExpressionFilter(log)})
	assert.NoError(t, err)
	ev := v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{Process: &tetragon.Process{Pid: wrapperspb.UInt32(1)}},
			},
		},
	}
	assert.False(t, fl.MatchOne(&ev))
	ev = v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{Process: &tetragon.Process{Pid: wrapperspb.UInt32(2)}},
			},
		},
	}
	assert.True(t, fl.MatchOne(&ev))
}

func TestProcessKprobeFilter(t *testing.T) {
	log := logrus.New()
	f := []*tetragon.Filter{{CelExpression: []string{"process_kprobe.function_name == 'security_file_permission'"}}}
	fl, err := BuildFilterList(context.Background(), f, []OnBuildFilter{NewCELExpressionFilter(log)})
	assert.NoError(t, err)
	ev := v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessKprobe{
				ProcessKprobe: &tetragon.ProcessKprobe{FunctionName: "security_file_permission"}},
		},
	}
	assert.True(t, fl.MatchOne(&ev))
	ev = v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessKprobe{
				ProcessKprobe: &tetragon.ProcessKprobe{FunctionName: "something_else"}},
		},
	}
	assert.False(t, fl.MatchOne(&ev))
}

func TestCIDR(t *testing.T) {
	log := logrus.New()
	f := []*tetragon.Filter{{CelExpression: []string{"cidr('10.0.0.0/16').containsIP(process_kprobe.args[0].sock_arg.saddr)"}}}
	fl, err := BuildFilterList(context.Background(), f, []OnBuildFilter{NewCELExpressionFilter(log)})
	assert.NoError(t, err)
	ev := v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessKprobe{
				ProcessKprobe: &tetragon.ProcessKprobe{Args: []*tetragon.KprobeArgument{{Arg: &tetragon.KprobeArgument_SockArg{SockArg: &tetragon.KprobeSock{Saddr: "10.0.2.21"}}}}}},
		},
	}
	assert.True(t, fl.MatchOne(&ev))
	ev = v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessKprobe{
				ProcessKprobe: &tetragon.ProcessKprobe{Args: []*tetragon.KprobeArgument{{Arg: &tetragon.KprobeArgument_SockArg{SockArg: &tetragon.KprobeSock{Saddr: "192.0.2.21"}}}}}},
		},
	}
	assert.False(t, fl.MatchOne(&ev))
}

func TestIP(t *testing.T) {
	log := logrus.New()
	f := []*tetragon.Filter{{CelExpression: []string{"ip(process_kprobe.args[0].sock_arg.saddr).family() == 4"}}}
	fl, err := BuildFilterList(context.Background(), f, []OnBuildFilter{NewCELExpressionFilter(log)})
	assert.NoError(t, err)
	ev := v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessKprobe{
				ProcessKprobe: &tetragon.ProcessKprobe{Args: []*tetragon.KprobeArgument{{Arg: &tetragon.KprobeArgument_SockArg{SockArg: &tetragon.KprobeSock{Saddr: "10.0.2.21"}}}}}},
		},
	}
	assert.True(t, fl.MatchOne(&ev))
	ev = v1.Event{
		Event: &tetragon.GetEventsResponse{
			Event: &tetragon.GetEventsResponse_ProcessKprobe{
				ProcessKprobe: &tetragon.ProcessKprobe{Args: []*tetragon.KprobeArgument{{Arg: &tetragon.KprobeArgument_SockArg{SockArg: &tetragon.KprobeSock{Saddr: "2001:db8::abcd"}}}}}},
		},
	}
	assert.False(t, fl.MatchOne(&ev))
}
