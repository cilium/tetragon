// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/base"
	testsensor "github.com/cilium/tetragon/pkg/sensors/test"
	"github.com/cilium/tetragon/pkg/testutils"
	"github.com/cilium/tetragon/pkg/testutils/perfring"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/google/go-cmp/cmp"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// TestTracepointSelectors tests the tracepoint selectors.
//
// It is different from the tests in tracepioint_test.go in that:
//   - it directly reads from the ringbuffer
// As other tracepoint tests, it uses the lseek system call with a bogus whence value.
func TestTracepointSelectors(t *testing.T) {
	testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))
	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	// The whence argument has a 7 index, see:
	// # cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_lseek/format
	// name: sys_enter_lseek
	// ID: 698
	// format:
	//         field:unsigned short common_type;       offset:0;       size:2; signed:0;
	//         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
	//         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
	//         field:int common_pid;   offset:4;       size:4; signed:1;
	//
	//         field:int __syscall_nr; offset:8;       size:4; signed:1;
	//         field:unsigned int fd;  offset:16;      size:8; signed:0;
	//         field:off_t offset;     offset:24;      size:8; signed:0;
	//         field:unsigned int whence;      offset:32;      size:8; signed:0;
	whenceIdx := uint32(7)

	// makeSpec returns a tracing policy spec for sys_enter_lseek.
	// It will create filters:
	//  - for our pid, to get more predictable events
	//  - for the whence values provided as argument (if any)
	makeSpec := func(t *testing.T, filterWhenceVals []int) *v1alpha1.TracingPolicySpec {
		mypid := int(observer.GetMyPid())
		t.Logf("filtering for my pid (%d)", mypid)
		sels := []v1alpha1.KProbeSelector{{
			MatchPIDs: []v1alpha1.PIDSelector{{
				Operator:       "In",
				IsNamespacePID: false,
				FollowForks:    true,
				Values:         []uint32{uint32(mypid)},
			}}}}

		if len(filterWhenceVals) > 0 {
			whences := make([]string, len(filterWhenceVals))
			for i := range filterWhenceVals {
				whences[i] = fmt.Sprintf("%d", filterWhenceVals[i])
			}
			sels[0].MatchArgs = []v1alpha1.ArgSelector{
				{
					Index:    whenceIdx,
					Operator: "Equal",
					Values:   whences,
				},
			}
		}

		spec := v1alpha1.TracingPolicySpec{
			Tracepoints: []v1alpha1.TracepointSpec{{
				Subsystem: "syscalls",
				Event:     "sys_enter_lseek",
				Args:      []v1alpha1.KProbeArg{{Index: whenceIdx}},
				Selectors: sels,
			}},
		}

		return &spec
	}

	// loadSensor loads a sensor
	loadSensor := func(t *testing.T, spec *v1alpha1.TracingPolicySpec) *sensors.Sensor {
		ret, err := sensors.GetSensorsFromParserPolicy(spec)
		if err != nil {
			t.Fatalf("GetSensorsFromParserPolicy failed: %v", err)
		} else if len(ret) != 1 {
			t.Fatalf("GetSensorsFromParserPolicy returned unexpected number of sensors (%d)", len(ret))
		}
		tpSensor := ret[0]
		option.Config.HubbleLib = tus.Conf().TetragonLib
		option.Config.Verbosity = 5
		tus.LoadSensor(ctx, t, base.GetInitialSensor())
		tus.LoadSensor(ctx, t, testsensor.GetTestSensor())
		tus.LoadSensor(ctx, t, tpSensor)
		return tpSensor
	}

	// lseekOps retruns a function to perform test lseek operations using the given whence
	// values
	lseekOps := func(whences []int) func(t *testing.T) {
		return func(t *testing.T) {
			for _, whence := range whences {
				t.Logf("Calling lseek(-1,0,%d)", whence)
				unix.Seek(-1, 0, whence)
			}
		}
	}

	// runAndCheck runs perfring test where op is exected and events are collected.
	// expectedArgs is a counter for the whence values seen by events, and is checked at the end
	// of the test.
	runAndCheck := func(t *testing.T, name string, op func(t *testing.T), expectedArgs map[uint64]int) {
		ret := make(map[uint64]int)
		perfring.RunSubTest(t, ctx, name, op, func(ev notify.Message) error {
			if tpEvent, ok := ev.(*tracing.MsgGenericTracepointUnix); ok {
				if tpEvent.Subsys != "syscalls" || tpEvent.Event != "sys_enter_lseek" {
					return fmt.Errorf("unexpected tracepoint event: %s:%s", tpEvent.Subsys, tpEvent.Event)
				}
				if len(tpEvent.Args) != 1 {
					return fmt.Errorf("unexpected tracepoint arguments: %+v", tpEvent.Args)
				}
				whence, ok := tpEvent.Args[0].(uint64)
				if !ok {
					return fmt.Errorf("unexpected tracepoint arguments %+v", tpEvent.Args[0])
				}

				// the test sensor also uses the same trick: an lseek call with a
				// bogus whence value. Ignore those events
				if whence == uint64(testsensor.BogusWhenceVal) {
					return nil
				}

				ret[whence] = ret[whence] + 1
			}
			return nil
		})
		if diff := cmp.Diff(expectedArgs, ret); diff != "" {
			t.Fatalf("expecting %v but got %v, diff:%s", expectedArgs, ret, diff)
		}
	}

	t0 := time.Now()
	loadSensor(t, makeSpec(t, []int{4443}))
	loadElapsed := time.Since(t0)
	t.Logf("loading sensors took: %s\n", loadElapsed)

	t.Run("initial sensor", func(t *testing.T) {
		testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))
		runAndCheck(t, "two events", lseekOps([]int{4444, 4443}), map[uint64]int{4443: 1})
	})
}
