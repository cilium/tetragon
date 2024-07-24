// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

// NB(kkourt): Function(t *testing.T, ctx context.Context) is the reasonable
// thing to do here even if revive complains.
//revive:disable:context-as-argument

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
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/base"
	testsensor "github.com/cilium/tetragon/pkg/sensors/test"
	"github.com/cilium/tetragon/pkg/testutils"
	"github.com/cilium/tetragon/pkg/testutils/perfring"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/google/go-cmp/cmp"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// loadGenericSensorTest loads a tracing sensor for testing
func loadGenericSensorTest(t *testing.T, spec *v1alpha1.TracingPolicySpec) *sensors.Sensor {
	if err := observer.InitDataCache(1024); err != nil {
		t.Fatalf("observertesthelper.InitDataCache: %s", err)
	}

	tp := &tracingpolicy.GenericTracingPolicy{
		Metadata: v1.ObjectMeta{Name: "name"},
		Spec:     *spec,
	}

	tus.LoadSensor(t, base.GetInitialSensor())
	tus.LoadSensor(t, testsensor.GetTestSensor())

	ret, err := sensors.SensorsFromPolicy(tp, policyfilter.NoFilterID)
	if err != nil {
		t.Fatalf("GetSensorsFromParserPolicy failed: %v", err)
	} else if len(ret) != 1 {
		t.Fatalf("GetSensorsFromParserPolicy returned unexpected number of sensors (%d)", len(ret))
	}
	tpSensor := ret[0]
	option.Config.HubbleLib = tus.Conf().TetragonLib
	tus.LoadSensor(t, tpSensor)
	return tpSensor.(*sensors.Sensor)
}

// lseekTestOps retruns a function to perform test lseek operations using the
// given whence values
func lseekTestOps(whences []int) func(t *testing.T) {
	return func(t *testing.T) {
		for _, whence := range whences {
			t.Logf("Calling lseek(-1,0,%d)", whence)
			unix.Seek(-1, 0, whence)
		}
	}
}

type testCase struct {
	// the test will perform a series of (bogys) lseek cols using the provided values as a whence argumetn
	lseekOpsVals []int
	// the expectedArgs are a map from whence values to the frequency they were observed in the events
	expectedArgs map[uint64]int
}

// testCases defines the use-cases we want to test
var testCases = []struct {
	// specOperator is the operator that will be used in the generated spec
	specOperator string
	// specFilterVals is the values that will be used in the generated
	// spec. The first dimension is the selector and the second is the
	// values to set for the lseek whence value.
	specFilterVals [][]int
	// the cases to actually test given the above spec properties
	tests []testCase
}{
	{
		specOperator:   "Equal",
		specFilterVals: [][]int{{4443}, {9999}},
		tests: []testCase{
			{lseekOpsVals: []int{4444, 4443}, expectedArgs: map[uint64]int{4443: 1}},
			{lseekOpsVals: []int{4443, 4444, 4443}, expectedArgs: map[uint64]int{4443: 2}},
			{lseekOpsVals: []int{9999, 4443}, expectedArgs: map[uint64]int{4443: 1, 9999: 1}},
			{lseekOpsVals: []int{9999, 4444}, expectedArgs: map[uint64]int{9999: 1}},
		},
	},
	{
		specOperator:   "Equal",
		specFilterVals: [][]int{{4444}, {9999}},
		tests: []testCase{
			{lseekOpsVals: []int{4444, 4443}, expectedArgs: map[uint64]int{4444: 1}},
			{lseekOpsVals: []int{4443, 4444, 4443}, expectedArgs: map[uint64]int{4444: 1}},
			{lseekOpsVals: []int{9999, 4443}, expectedArgs: map[uint64]int{9999: 1}},
			{lseekOpsVals: []int{9999, 4444}, expectedArgs: map[uint64]int{9999: 1, 4444: 1}},
		},
	},
	{
		// NB: this needs to be first
		specOperator:   "InMap",
		specFilterVals: [][]int{{8888, 8889}, {4442, 4443, 4444}},
		tests: []testCase{
			{lseekOpsVals: []int{4444, 4445}, expectedArgs: map[uint64]int{4444: 1}},
			{lseekOpsVals: []int{4443, 8889}, expectedArgs: map[uint64]int{4443: 1, 8889: 1}},
		},
	},
	{
		specOperator:   "InMap",
		specFilterVals: [][]int{{4443}, {9999}},
		tests: []testCase{
			{lseekOpsVals: []int{4444, 4443}, expectedArgs: map[uint64]int{4443: 1}},
			{lseekOpsVals: []int{4443, 4444, 4443}, expectedArgs: map[uint64]int{4443: 2}},
			{lseekOpsVals: []int{9999, 4443}, expectedArgs: map[uint64]int{4443: 1, 9999: 1}},
			{lseekOpsVals: []int{9999, 4444}, expectedArgs: map[uint64]int{9999: 1}},
		},
	},
	{
		specOperator:   "InMap",
		specFilterVals: [][]int{{4444}, {9999}},
		tests: []testCase{
			{lseekOpsVals: []int{4444, 4443}, expectedArgs: map[uint64]int{4444: 1}},
			{lseekOpsVals: []int{4443, 4444, 4443}, expectedArgs: map[uint64]int{4444: 1}},
			{lseekOpsVals: []int{9999, 4443}, expectedArgs: map[uint64]int{9999: 1}},
			{lseekOpsVals: []int{9999, 4444}, expectedArgs: map[uint64]int{9999: 1, 4444: 1}},
		},
	},
	{
		specOperator:   "Equal",
		specFilterVals: [][]int{{8888}, {8889}, {4443}},
		tests: []testCase{
			{lseekOpsVals: []int{4444, 4443}, expectedArgs: map[uint64]int{4443: 1}},
		},
	},
}

// TestTracepointSelectors tests the tracepoint selectors.
//
// It is different from the tests in tracepioint_test.go in that:
//   - it directly reads from the ringbuffer
//   - it test different configurations by detaching (unlinking) the tracepoint hook, update the
//     cosnfiguration, and relinking. This means that verification for every test happens only once,
//     significantly reducing test time.
//
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
	makeSpec := func(t *testing.T, filterWhenceVals [][]int, filterOperator string) *v1alpha1.TracingPolicySpec {
		sels := selectorsFromWhenceVals(t, filterWhenceVals, whenceIdx, filterOperator)
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

	// runAndCheck runs perfring test where op is exected and events are collected.
	// expectedArgs is a counter for the whence values seen by events, and is
	// checked at the end of the test.
	runAndCheck := func(t *testing.T, ctx context.Context, name string, op func(t *testing.T), expectedArgs map[uint64]int) {
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

	for _, tcs := range testCases {
		tName := fmt.Sprintf("spec:%s%v", tcs.specOperator, tcs.specFilterVals)
		t.Run(tName, func(t *testing.T) {
			testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))
			t.Logf("Running %s", tName)
			t0 := time.Now()
			spec := makeSpec(t, tcs.specFilterVals, tcs.specOperator)
			tpSensor := loadGenericSensorTest(t, spec)
			loadElapsed := time.Since(t0)
			t.Logf("loading sensors (tpSensor: %p)  took: %s\n", tpSensor, loadElapsed)
			for _, tc := range tcs.tests {
				runAndCheck(t, ctx, fmt.Sprintf("lseekValls:%v", tc.lseekOpsVals), lseekTestOps(tc.lseekOpsVals), tc.expectedArgs)
			}
		})
	}
}

func selectorsFromWhenceVals(t *testing.T, filterWhenceVals [][]int, whenceIdx uint32, filterOperator string) []v1alpha1.KProbeSelector {
	sels := []v1alpha1.KProbeSelector{}
	mypid := int(observertesthelper.GetMyPid())
	t.Logf("filtering for my pid (%d)", mypid)
	myPidMatchPIDs := []v1alpha1.PIDSelector{{
		Operator:       "In",
		IsNamespacePID: false,
		FollowForks:    true,
		Values:         []uint32{uint32(mypid)},
	}}

	for _, whenceVals := range filterWhenceVals {
		whences := make([]string, len(whenceVals))
		for i := range whenceVals {
			whences[i] = fmt.Sprintf("%d", whenceVals[i])
		}
		sels = append(sels, v1alpha1.KProbeSelector{
			MatchPIDs: myPidMatchPIDs,
			MatchArgs: []v1alpha1.ArgSelector{{
				Index:    whenceIdx,
				Operator: filterOperator,
				Values:   whences,
			}},
		})
	}

	if len(sels) == 0 {
		sel := v1alpha1.KProbeSelector{
			MatchPIDs: myPidMatchPIDs,
		}

		sels = append(sels, sel)
	}

	return sels
}

func TestKprobeSelectors(t *testing.T) {
	testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))
	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	makeSpec := func(t *testing.T, filterWhenceVals [][]int, filterOperator string) *v1alpha1.TracingPolicySpec {
		sels := selectorsFromWhenceVals(t, filterWhenceVals, 2 /* whenceIdx */, filterOperator)
		spec := v1alpha1.TracingPolicySpec{
			KProbes: []v1alpha1.KProbeSpec{{
				Call:    "sys_lseek",
				Return:  true,
				Syscall: true,
				ReturnArg: &v1alpha1.KProbeArg{
					Type: "int",
				},
				Args: []v1alpha1.KProbeArg{{
					Index: 2,
					Type:  "int",
				}},
				Selectors: sels,
			}},
		}

		return &spec
	}

	// runAndCheck runs perfring test where op is exected and events are collected.
	// expectedArgs is a counter for the whence values seen by events, and is
	// checked at the end of the test.
	runAndCheck := func(t *testing.T, ctx context.Context, name string, op func(t *testing.T), expectedArgs map[uint64]int) {
		ret := make(map[uint64]int)
		perfring.RunSubTest(t, ctx, name, op, func(ev notify.Message) error {
			if kpEvent, ok := ev.(*tracing.MsgGenericKprobeUnix); ok {
				if kpEvent.FuncName != arch.AddSyscallPrefixTestHelper(t, "sys_lseek") {
					return fmt.Errorf("unexpected kprobe event, func:%s", kpEvent.FuncName)
				}
				if len(kpEvent.Args) != 2 {
					return fmt.Errorf("unexpected kprobe arguments: %+v", kpEvent.Args)
				}
				whenceArg, ok := kpEvent.Args[0].(tracingapi.MsgGenericKprobeArgInt)
				if !ok {
					return fmt.Errorf("unexpected kprobe arguments %+v", kpEvent.Args[0])
				}

				retArg, ok := kpEvent.Args[1].(tracingapi.MsgGenericKprobeArgInt)
				if !ok {
					return fmt.Errorf("unexpected kprobe arguments %+v", kpEvent.Args[0])
				}
				if retArg.Value != -9 { // -EBADF
					return fmt.Errorf("unexpected return value: %+v", retArg)
				}

				whence := uint64(whenceArg.Value)
				// the test sensor also uses the same trick: an lseek call with a
				// bogus whence value. Ignore those events
				if whence == uint64(testsensor.BogusWhenceVal) {
					return nil
				}

				ret[whence] = ret[whence] + 1
				return nil
			}
			return nil
		})
		if diff := cmp.Diff(expectedArgs, ret); diff != "" {
			t.Fatalf("expecting %v but got %v, diff:%s", expectedArgs, ret, diff)
		}
	}

	for _, tcs := range testCases {
		tName := fmt.Sprintf("spec:%s%v", tcs.specOperator, tcs.specFilterVals)
		t.Run(tName, func(t *testing.T) {
			testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))
			t.Logf("Running %s", tName)

			t0 := time.Now()
			spec := makeSpec(t, tcs.specFilterVals, tcs.specOperator)
			kpSensor := loadGenericSensorTest(t, spec)
			loadElapsed := time.Since(t0)
			t.Logf("loading sensors (kpSensor: %p)  took: %s\n", kpSensor, loadElapsed)

			for _, tc := range tcs.tests {
				runAndCheck(t, ctx, fmt.Sprintf("lseekValls:%v", tc.lseekOpsVals), lseekTestOps(tc.lseekOpsVals), tc.expectedArgs)
			}
		})
	}

}
