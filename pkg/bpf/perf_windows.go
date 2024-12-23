// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"fmt"
	"path/filepath"
	"runtime"

	"github.com/cilium/ebpf"
)

type PerfEventConfig struct {
	NumCpus      int
	NumPages     int
	MapName      string
	Type         int
	Config       int
	SampleType   int
	WakeupEvents int
}

func GetNumPossibleCPUs() int {
	nCpus, err := ebpf.PossibleCPU()
	if err != nil {
		nCpus = runtime.NumCPU()
	}
	return nCpus
}

// DefaultPerfEventConfig returns the default perf event configuration. It
// relies on the map root to be set.
func DefaultPerfEventConfig() *PerfEventConfig {
	return &PerfEventConfig{
		MapName:      filepath.Join(MapPrefixPath(), eventsMapName),
		Type:         PERF_TYPE_SOFTWARE,
		Config:       PERF_COUNT_SW_BPF_OUTPUT,
		SampleType:   PERF_SAMPLE_RAW,
		WakeupEvents: 1,
		NumCpus:      GetNumPossibleCPUs(),
		NumPages:     128,
	}
}

func UpdateElementFromPointers(fd int, structPtr, sizeOfStruct uintptr) error {
	//ToDo: use libbpf.dll!bpf()
	// ret, _, err := unix.Syscall(
	// 	unix.SYS_BPF,
	// 	BPF_MAP_UPDATE_ELEM,
	// 	structPtr,
	// 	sizeOfStruct,
	// )
	// if ret != 0 || err != 0 {
	// 	return fmt.Errorf("Unable to update element for map with file descriptor %d: %s", fd, err)
	// }
	return fmt.Errorf("not supported on windows")
}
