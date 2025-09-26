// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package errmetrics

import "fmt"

// Keep in sync with bpf/errmetrics/fileids.h.
var Files = map[uint8]string{
	1: "bpf_cgtracker.c",
	2: "bpf_cgroup_mkdir.c",
	3: "bpf_enforcer.h",
	4: "bpf_alignchecker.c",
	5: "retprobe_map.h",
	6: "generic_path.h",
	7: "bpf_generic_tracepoint.c",
	8: "process.h",
	9: "bpf_execve_event.c",
}

func BPFFileName(id uint8) string {
	if name, ok := Files[id]; ok {
		return name
	}
	return fmt.Sprintf("unknown(%d)", id)
}
