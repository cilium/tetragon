// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tracing

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/arch"
	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/cilium/tetragon/pkg/testutils"
	"github.com/cilium/tetragon/pkg/testutils/perfring"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestCharBufKprobe(t *testing.T) {
	testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))
	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	mypid := int(observertesthelper.GetMyPid())
	t.Logf("filtering for my pid (%d)", mypid)

	writeBufArgIdx := uint32(1)
	writeSizeArgIdx := uint32(2)
	writeBufArg := "pizzaisthebest"
	call := "sys_write"
	spec := &v1alpha1.TracingPolicySpec{
		KProbes: []v1alpha1.KProbeSpec{{
			Call:    call,
			Syscall: true,
			Args: []v1alpha1.KProbeArg{{
				Index:        writeBufArgIdx,
				Type:         "char_buf",
				SizeArgIndex: writeSizeArgIdx + 1,
			}, {
				Index: writeSizeArgIdx,
				Type:  "size_t",
			}},
			Selectors: []v1alpha1.KProbeSelector{{
				MatchPIDs: []v1alpha1.PIDSelector{{
					Operator:    "In",
					FollowForks: true,
					Values:      []uint32{uint32(mypid)},
				}},
				MatchArgs: []v1alpha1.ArgSelector{{
					Index:    writeBufArgIdx,
					Operator: "Equal",
					Values:   []string{writeBufArg},
				}},
			}},
		}},
	}

	loadGenericSensorTest(t, spec)
	t0 := time.Now()
	loadElapsed := time.Since(t0)
	t.Logf("loading sensors took: %s\n", loadElapsed)

	countPizza := 0
	countOther := 0
	eventFn := func(ev notify.Message) error {
		if kpEvent, ok := ev.(*tracing.MsgGenericKprobeUnix); ok {
			if kpEvent.FuncName != arch.AddSyscallPrefixTestHelper(t, call) {
				return fmt.Errorf("unexpected kprobe event, func:%s", kpEvent.FuncName)
			}
			arg := string(kpEvent.Args[0].(tracingapi.MsgGenericKprobeArgBytes).Value)
			if arg == writeBufArg {
				countPizza++
			} else {
				countOther++
			}
		}
		return nil
	}

	ops := func() {
		unix.Write(-1, []byte(writeBufArg))
		unix.Write(-1, []byte("unrelated string"))
	}

	perfring.RunTest(t, ctx, ops, eventFn)
	require.Equal(t, 1, countPizza, "expected events with '%s'", writeBufArg)
	require.Equal(t, 0, countOther, "unexexpected events")

}

func TestCharBufTracepoint(t *testing.T) {
	testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))
	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	mypid := int(observertesthelper.GetMyPid())
	t.Logf("filtering for my pid (%d)", mypid)

	writeBufArgIdx := uint32(6)
	writeSizeArgIdx := uint32(7)
	writeBufArg := "pizzaisthebest"
	event := "sys_enter_write"
	spec := &v1alpha1.TracingPolicySpec{
		Tracepoints: []v1alpha1.TracepointSpec{{
			Subsystem: "syscalls",
			Event:     event,
			Args: []v1alpha1.KProbeArg{{
				Index:        writeBufArgIdx,
				Type:         "char_buf",
				SizeArgIndex: writeSizeArgIdx + 1,
			}, {
				Index: writeSizeArgIdx,
				Type:  "size_t",
			}},
			Selectors: []v1alpha1.KProbeSelector{{
				MatchPIDs: []v1alpha1.PIDSelector{{
					Operator:    "In",
					FollowForks: true,
					Values:      []uint32{uint32(mypid)},
				}},
				MatchArgs: []v1alpha1.ArgSelector{{
					Index:    writeBufArgIdx,
					Operator: "Equal",
					Values:   []string{writeBufArg},
				}},
			}},
		}},
	}

	loadGenericSensorTest(t, spec)
	t0 := time.Now()
	loadElapsed := time.Since(t0)
	t.Logf("loading sensors took: %s\n", loadElapsed)

	countPizza := 0
	countOther := 0
	eventFn := func(ev notify.Message) error {
		if tpEvent, ok := ev.(*tracing.MsgGenericTracepointUnix); ok {
			if tpEvent.Event != event {
				return fmt.Errorf("unexpected tracepoint event, %s:%s", tpEvent.Subsys, tpEvent.Event)
			}
			arg := string(tpEvent.Args[0].([]byte))
			if arg == writeBufArg {
				countPizza++
			} else {
				countOther++
			}
		}
		return nil
	}

	ops := func() {
		unix.Write(-1, []byte(writeBufArg))
		unix.Write(-1, []byte("unrelated string"))
	}

	perfring.RunTest(t, ctx, ops, eventFn)
	require.Equal(t, 1, countPizza, "expected events with '%s'", writeBufArg)
	require.Equal(t, 0, countOther, "unexexpected events")
}
