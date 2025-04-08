// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package bpf

import "strconv"

/*uapi/linux/perfevent.h */
var perfEventTypeString = map[uint32]string{
	0: "PERF_TYPE_HARDWARE",
	1: "PERF_TYPE_SOFTWARE",
	2: "PERF_TYPE_TRACEPOINT",
	3: "PERF_TYPE_HW_CACHE",
	4: "PERF_TYPE_RAW",
	5: "PERF_TYPE_BREAKPOINT",
	6: "PERF_TYPE_MAX",
}

func GetPerfEventType(t uint32) string {
	if t, ok := perfEventTypeString[t]; ok {
		return t
	}
	return strconv.FormatUint(uint64(t), 10)
}
