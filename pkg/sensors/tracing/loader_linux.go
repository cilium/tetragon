package tracing

import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/cilium/tetragon/pkg/bpf"
	"golang.org/x/sys/unix"
)

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
