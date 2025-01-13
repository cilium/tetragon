// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

// The loader sensor hooks to perf_event_mmap_output function to get MMAP/MMAP2
// events, which is triggered any time a memory map is created in the system.
//
// To make kernel to call perf_event_mmap_output function we need to create
// perf events (for each cpu) with mmap/mmap2/build_id bits, so the perf code
// gathers all the needed data and the sensors can read it.
//
// We can't just simply monitor MMAP/MMAP2 events, because when running under
// kubernetes the perf subsystem converts pid/tid values into perf event owner's
// namespace.. so we get zero pid/tid for all processes executed outside tetragon
// namespace.
//
// The user side loader code:
// - setups perf events to get MMAP/MMAP2 events with build ids
// - loads perf events ids into bpf map
// - hooks bpf code to perf_event_mmap_output function
//
// The bpf/kernel side loader codr:
// - checks the perf event id matches the one from bpf map
// - reads needed data from perf event and sends LOADER event
//   to user space

package tracing

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"syscall"
	"unsafe"

	"github.com/cilium/tetragon/pkg/api/ops"
	"github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/grpc/tracing"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer"
	"github.com/cilium/tetragon/pkg/policyfilter"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/cilium/tetragon/pkg/sensors/program"
	"github.com/cilium/tetragon/pkg/strutils"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/sys/unix"
)

type cacheKey struct {
	Pid  uint32
	Path string
}

const (
	cacheSize = 1024
)

var (
	loader = program.Builder(
		"bpf_loader.o",
		"perf_event_mmap_output",
		"kprobe/perf_event_mmap_output",
		"loader_kprobe",
		"loader",
	)

	idsMap    = program.MapBuilder("ids_map", loader)
	execveMap = program.MapUser(base.ExecveMap.Name, loader)

	loaderEnabled bool

	cache *lru.Cache[cacheKey, bool]
)

type loaderSensor struct {
	name string
}

func init() {
	loader := &loaderSensor{
		name: "loader sensor",
	}
	sensors.RegisterProbeType("loader", loader)
	sensors.RegisterPolicyHandlerAtInit(loader.name, loader)

	observer.RegisterEventHandlerAtInit(ops.MSG_OP_LOADER, handleLoader)

	var err error
	cache, err = lru.NewWithEvict(
		cacheSize,
		func(_ cacheKey, _ bool) {
			// not used at the moment, let's see if we want to add metric for this
		},
	)
	if err != nil {
		log.Fatalf("loader init failed with %v", err)
	}

}

func GetLoaderSensor() *sensors.Sensor {
	return &sensors.Sensor{
		Name:  "__loader__",
		Progs: []*program.Program{loader},
		Maps:  []*program.Map{idsMap, execveMap},
	}
}

func hasLoaderEvents() bool {
	return bpf.HasBuildId() && kernels.MinKernelVersion("5.19.0")
}

func (k *loaderSensor) PolicyHandler(p tracingpolicy.TracingPolicy, fid policyfilter.PolicyID) (sensors.SensorIface, error) {
	spec := p.TpSpec()
	// NB: no loader section is the spec, so nothing to do
	if !spec.Loader {
		return nil, nil
	}

	if fid != policyfilter.NoFilterID {
		return nil, fmt.Errorf("loader sensor does not implement policy filtering")
	}

	if !hasLoaderEvents() {
		return nil, fmt.Errorf("Loader event are not supported on running kernel")
	}
	loaderEnabled = true
	return GetLoaderSensor(), nil
}

func createLoaderEvents() error {
	attr := &unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_SOFTWARE,
		Config:      unix.PERF_COUNT_SW_BPF_OUTPUT,
		Sample_type: unix.PERF_SAMPLE_RAW,

		// Enable all possible perf mmap events to increase the possibility
		// we get valid build id data for the binary.
		Bits: unix.PerfBitMmap | unix.PerfBitMmap2 | bpf.PerfBitBuildId |
			unix.PerfBitMmapData,
	}

	nCpus := bpf.GetNumPossibleCPUs()

	// We create perf event for each cpu and uploade their ids
	// into 'ids_map' for the bpf program to recognize our event.

	// We need this event to stay loaded, so we don't close it,
	// it stays opened until tetragon process exits.

	var ids []uint64

	for cpu := 0; cpu < nCpus; cpu++ {
		fd, err := unix.PerfEventOpen(attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
		if err != nil {
			return fmt.Errorf("can't create perf event: %w", err)
		}

		var id int

		_, _, errno := syscall.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.PERF_EVENT_IOC_ID, uintptr(unsafe.Pointer(&id)))
		if errno != 0 {
			return fmt.Errorf("failed to get perf event id for fd %d: %w", fd, err)
		}
		ids = append(ids, uint64(id))
	}

	key := uint32(0)
	err := idsMap.MapHandle.Put(key, ids[0:])
	if err != nil {
		return fmt.Errorf("failed to update ids_map: %w", err)
	}
	return nil
}

func (k *loaderSensor) LoadProbe(args sensors.LoadProbeArgs) error {
	if loaderEnabled {
		if err := createLoaderEvents(); err != nil {
			return err
		}
		return program.LoadKprobeProgram(args.BPFDir, args.Load, args.Verbose)
	}
	return nil
}

func inCache(pid uint32, path string) bool {
	key := cacheKey{pid, path}
	_, ok := cache.Get(key)
	if !ok {
		cache.Add(key, true)
	}
	return ok
}

func handleLoader(r *bytes.Reader) ([]observer.Event, error) {
	m := tracingapi.MsgLoader{}
	err := binary.Read(r, binary.LittleEndian, &m)
	if err != nil {
		logger.GetLogger().WithError(err).Warnf("Failed to read process call msg")
		return nil, fmt.Errorf("Failed to read process call msg")
	}

	path := m.Path[:m.PathSize-1]

	// We can get multiple entries for given pid/path,
	// check if we already processed it
	if inCache(m.Pid, string(path[:])) {
		return nil, nil
	}

	msg := &tracing.MsgProcessLoaderUnix{
		Msg:     &m,
		Path:    strutils.UTF8FromBPFBytes(path),
		Buildid: m.BuildId[:m.BuildIdSize],
	}
	return []observer.Event{msg}, nil
}
