// Copyright 2016-2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bpf

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	PossibleCPUSysfsPath = "/sys/devices/system/cpu/possible"
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

// GetNumPossibleCPUs returns a total number of possible CPUS, i.e. CPUs that
// have been allocated resources and can be brought online if they are present.
// The number is retrieved by parsing /sys/device/system/cpu/possible.
//
// See https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/cpumask.h?h=v4.19#n50
// for more details.
func GetNumPossibleCPUs() int {
	f, err := os.Open(PossibleCPUSysfsPath)
	if err != nil {
		return 0
	}
	defer f.Close()

	return getNumPossibleCPUsFromReader(f)
}

func getNumPossibleCPUsFromReader(r io.Reader) int {
	out, err := io.ReadAll(r)
	if err != nil {
		return 0
	}

	var start, end int
	count := 0
	for _, s := range strings.Split(string(out), ",") {
		// Go's scanf will return an error if a format cannot be fully matched.
		// So, just ignore it, as a partial match (e.g. when there is only one
		// CPU) is expected.
		n, _ := fmt.Sscanf(s, "%d-%d", &start, &end)

		switch n {
		case 0:
			return 0
		case 1:
			count++
		default:
			count += (end - start + 1)
		}
	}

	return count
}

// DefaultPerfEventConfig returns the default perf event configuration. It
// relies on the map root to be set.
func DefaultPerfEventConfig() *PerfEventConfig {
	numCpus := GetNumPossibleCPUs()
	if numCpus == 0 {
		numCpus = runtime.NumCPU()
	}
	return &PerfEventConfig{
		MapName:      filepath.Join(MapPrefixPath(), eventsMapName),
		Type:         PERF_TYPE_SOFTWARE,
		Config:       PERF_COUNT_SW_BPF_OUTPUT,
		SampleType:   PERF_SAMPLE_RAW,
		WakeupEvents: 1,
		NumCpus:      numCpus,
		NumPages:     128,
	}
}

func UpdateElementFromPointers(fd int, structPtr, sizeOfStruct uintptr) error {
	ret, _, err := unix.Syscall(
		unix.SYS_BPF,
		BPF_MAP_UPDATE_ELEM,
		structPtr,
		sizeOfStruct,
	)
	if ret != 0 || err != 0 {
		return fmt.Errorf("Unable to update element for map with file descriptor %d: %s", fd, err)
	}
	return nil
}
