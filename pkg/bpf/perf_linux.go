// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	PossibleCPUSysfsPath = "/sys/devices/system/cpu/possible"
)

type PerfEventConfig struct {
	MapName string
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
	return &PerfEventConfig{
		MapName: filepath.Join(MapPrefixPath(), eventsMapName),
	}
}
