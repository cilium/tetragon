// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package cgrouprate

import (
	"os"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/reader/notify"
	"github.com/cilium/tetragon/pkg/sensors/program"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/stretchr/testify/assert"
)

func TestMain(m *testing.M) {
	ec := tus.TestSensorsRun(m, "SensorExec")
	os.Exit(ec)
}

type listener struct {
	throttle tetragon.ThrottleType
	cgroup   string
}

func (l *listener) Notify(msg notify.Message) error {
	response := msg.HandleMessage()
	switch response.Event.(type) {
	case *tetragon.GetEventsResponse_ProcessThrottle:
		ev := response.GetProcessThrottle()
		l.throttle = ev.Type
		l.cgroup = ev.Cgroup
	}
	return nil
}

func (l *listener) Close() error {
	return nil
}

type testData struct {
	opts     option.CgroupRate
	values   [2]processapi.CgroupRateValue
	last     uint64
	throttle tetragon.ThrottleType
	ret      bool
}

func TestProcessCgroup(t *testing.T) {
	key := processapi.CgroupRateKey{
		ID: 123,
	}

	cgroup := "cgroup"

	// Test that we get (or not) STOP throttle event, which depends on
	// wether the cgroup is alive and the rate is below the limit.

	data := []testData{
		// 0: both rate and last time update are beyond limit on both
		// cpus - expecting STOP
		{
			opts: option.CgroupRate{
				Events:   10,
				Interval: uint64(time.Second),
			},
			values: [2]processapi.CgroupRateValue{
				{
					Rate:      1,
					Time:      uint64(time.Second),
					Throttled: uint64(time.Second),
				},
				{
					Rate:      2,
					Time:      uint64(time.Second),
					Throttled: uint64(time.Second),
				},
			},
			last: uint64(time.Second) * 8,

			// expecting:
			throttle: tetragon.ThrottleType_THROTTLE_STOP,
			ret:      true,
		},
		// 1: rate is above limit and last time update is recent enough from
		// rate time - no event
		{
			opts: option.CgroupRate{
				Events:   10,
				Interval: uint64(time.Second),
			},
			values: [2]processapi.CgroupRateValue{
				{
					Rate:      1,
					Time:      uint64(time.Second),
					Throttled: uint64(time.Second),
				},
				{
					Rate:      2,
					Time:      uint64(time.Second),
					Throttled: uint64(time.Second),
				},
			},
			last: uint64(time.Second),

			// expecting:
			throttle: tetragon.ThrottleType_THROTTLE_UNKNOWN,
			ret:      false,
		},
		// 2: rate is below limit but last time update is recent enough from
		// throttle time - expecting no event
		{
			opts: option.CgroupRate{
				Events:   10,
				Interval: uint64(time.Second),
			},
			values: [2]processapi.CgroupRateValue{
				{
					Rate:      1,
					Time:      uint64(time.Second * 3),
					Throttled: uint64(time.Second),
				},
				{
					Rate:      2,
					Time:      uint64(time.Second * 3),
					Throttled: uint64(time.Second),
				},
			},
			last: uint64(time.Second * 3),

			// expecting:
			throttle: tetragon.ThrottleType_THROTTLE_UNKNOWN,
			ret:      false,
		},
		// 3: rate is below limit but last time update is recent enough from
		// throttle time on one cpu, the other one is dead - expecting no event
		{
			opts: option.CgroupRate{
				Events:   10,
				Interval: uint64(time.Second),
			},
			values: [2]processapi.CgroupRateValue{
				{
					Rate:      0,
					Time:      uint64(time.Second),
					Throttled: uint64(time.Second),
				},
				{
					Rate:      2,
					Time:      uint64(time.Second * 10),
					Throttled: uint64(time.Second * 5),
				},
			},
			last: uint64(time.Second * 7),

			// expecting:
			throttle: tetragon.ThrottleType_THROTTLE_UNKNOWN,
			ret:      false,
		},
		// 4: rate is above limit, but the last time update is beyond limit on
		// both cpus - expecting STOP
		{
			opts: option.CgroupRate{
				Events:   10,
				Interval: uint64(time.Second),
			},
			values: [2]processapi.CgroupRateValue{
				{
					Rate:      20,
					Time:      uint64(time.Second),
					Throttled: uint64(time.Second),
				},
				{
					Rate:      20,
					Time:      uint64(time.Second),
					Throttled: uint64(time.Second),
				},
			},
			last: uint64(time.Second) * 8,

			// expecting:
			throttle: tetragon.ThrottleType_THROTTLE_STOP,
			ret:      true,
		},
		// 5: rate is below limit and the last time is recent enough on
		// both cpus - expecting STOP
		{
			opts: option.CgroupRate{
				Events:   10,
				Interval: uint64(time.Second),
			},
			values: [2]processapi.CgroupRateValue{
				{
					Rate:      2,
					Time:      uint64(time.Second * 8),
					Throttled: uint64(time.Second),
				},
				{
					Rate:      3,
					Time:      uint64(time.Second * 8),
					Throttled: uint64(time.Second),
				},
			},
			last: uint64(time.Second * 9),

			// expecting:
			throttle: tetragon.ThrottleType_THROTTLE_STOP,
			ret:      true,
		},
	}

	values := make([]processapi.CgroupRateValue, bpf.GetNumPossibleCPUs())

	spec := &ebpf.MapSpec{
		Type:       ebpf.PerCPUHash,
		KeySize:    uint32(unsafe.Sizeof(key)),
		ValueSize:  uint32(unsafe.Sizeof(values[0])),
		MaxEntries: 32768,
	}

	load := program.Builder("", "", "", "", "")
	hash := program.MapBuilder("hash", load)
	err := hash.New(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer hash.Close()

	for idx, d := range data {
		l := &listener{
			throttle: tetragon.ThrottleType_THROTTLE_UNKNOWN,
		}
		NewTestCgroupRate(l, hash, &d.opts)

		// setup cgrouprate cgroup
		glSt.handle.cgroups[key.ID] = cgroup
		assert.NotNil(t, glSt.handle)

		// store hash values
		values[0] = d.values[0]
		values[1] = d.values[1]

		if err := hash.MapHandle.Put(key, values); err != nil {
			t.Fatal("Can't put:", err)
		}

		t.Logf("Test %d", idx)
		ret := glSt.handle.processCgroup(key.ID, cgroup, d.last)

		assert.Equal(t, d.ret, ret)
		assert.Equal(t, d.throttle, l.throttle)
	}
}

func TestParseCgroupRate(t *testing.T) {
	var opt option.CgroupRate

	// ok
	opt = option.ParseCgroupRate("1,1s")
	assert.Equal(t, option.CgroupRate{Events: 1, Interval: 1000000000}, opt)

	opt = option.ParseCgroupRate("1,1m")
	assert.Equal(t, option.CgroupRate{Events: 1, Interval: 60000000000}, opt)

	// fail
	empty := option.CgroupRate{Events: 0, Interval: 0}

	opt = option.ParseCgroupRate("10")
	assert.Equal(t, empty, opt)

	opt = option.ParseCgroupRate("sure,1s")
	assert.Equal(t, empty, opt)

	opt = option.ParseCgroupRate("1,nope")
	assert.Equal(t, empty, opt)
}
