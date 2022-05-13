// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package proc

import (
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	nanoPerSeconds = 1000000000

	// CLK_TCK is always constant 100 on all architectures except alpha and ia64 which are both
	// obsolete and not supported by TETRAGON. Also see
	// https://lore.kernel.org/lkml/agtlq6$iht$1@penguin.transmeta.com/ and
	// https://github.com/containerd/cgroups/pull/12
	clktck = uint64(100)
)

// The /proc/PID/stat file consists of a single line of space-separated strings, where
// the 2nd string contains the process' comm. This string is wrapped in brackets but can
// contain spaces and brackets. The correct way to parse this stat string is to find all
// space-separated strings working backwards from the end until a string is found that
// ends in a space, then find the first string and everything left must be the comm.
func getProcStatStrings(procStat string) []string {
	var output []string

	// Build list of strings in reverse order
	oldIndex := len(procStat)
	index := strings.LastIndexByte(procStat, ' ')
	for index > 0 {
		output = append(output, procStat[index+1:oldIndex])
		if procStat[index-1] == ')' {
			break
		}
		oldIndex = index
		index = strings.LastIndexByte(procStat[:oldIndex], ' ')
	}

	if index == -1 {
		// Did not hit ')'
		output = append(output, procStat[:oldIndex])
	} else {
		// Find the comm and first field
		commIndex := strings.IndexByte(procStat, ' ')
		output = append(output, procStat[commIndex+1:index])
		output = append(output, procStat[:commIndex])
	}

	// Reverse the array
	for i, j := 0, len(output)-1; i < j; i, j = i+1, j-1 {
		output[i], output[j] = output[j], output[i]
	}

	return output
}

func GetProcStatStrings(file string) ([]string, error) {
	statline, err := ioutil.ReadFile(filepath.Join(file, "stat"))
	if err != nil {
		return nil, fmt.Errorf("ReadFile: %s /stat error", file)
	}
	return getProcStatStrings(string(statline)), nil
}

func GetStatsKtime(s []string) (uint64, error) {
	ktime, err := strconv.ParseUint(s[21], 10, 64)
	if err != nil {
		return 0, err
	}
	return ktime * (nanoPerSeconds / clktck), nil
}

func GetProcPid(pid string) (uint64, error) {
	return strconv.ParseUint(pid, 10, 32)
}

func PrependPath(s string, b []byte) []byte {
	split := strings.Split(string(b), "\u0000")
	split[0] = s
	fullCmd := strings.Join(split[0:], "\u0000")
	return []byte(fullCmd)
}
