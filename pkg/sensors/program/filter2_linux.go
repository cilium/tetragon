// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package program

import (
	"slices"

	"github.com/cilium/ebpf"

	"github.com/cilium/tetragon/pkg/bpf"
)

// splitFilterProgs are the TAIL_CALL_FILTER_2 programs of the generic
// sensors. They are tail called only in split mode, when the process filter
// stages run in separate programs (see filter_run_stage_1/2() in
// bpf/process/generic_calls.h).
var splitFilterProgs = []string{
	"generic_kprobe_process_filter_2",
	"generic_uprobe_process_filter_2",
	"generic_usdt_process_filter_2",
	"generic_tracepoint_process_filter_2",
	"generic_rawtp_process_filter_2",
	"generic_lsm_process_filter_2",
	"generic_fentry_process_filter_2",
}

// dropSplitFilterProgs removes the TAIL_CALL_FILTER_2 programs from the spec
// when they can't be reached, so they are not loaded and verified for nothing.
func dropSplitFilterProgs(spec *ebpf.CollectionSpec) {
	dropSplitFilterProgsIf(spec, bpf.HasIterNum())
}

// dropSplitFilterProgsIf removes the TAIL_CALL_FILTER_2 programs from the spec
// if the object runs the process filter in a single program, which is when:
//   - numeric iterators are available (iterNum), so CONFIG(ITER_NUM) is 1, and
//   - the object reads ITER_NUM from the rodata config map at runtime. Objects
//     without that map (v53, small) have ITER_NUM compiled to 0 and always
//     run in split mode.
//
// The programs are also removed from the prog array contents, otherwise
// the collection loader would fail on (or load) the missing programs.
func dropSplitFilterProgsIf(spec *ebpf.CollectionSpec, iterNum bool) {
	if !iterNum || !hasRodataConfigMap(spec) {
		return
	}

	var dropped []string
	for _, name := range splitFilterProgs {
		if _, ok := spec.Programs[name]; ok {
			delete(spec.Programs, name)
			dropped = append(dropped, name)
		}
	}
	if len(dropped) == 0 {
		return
	}

	for _, ms := range spec.Maps {
		if ms.Type != ebpf.ProgramArray {
			continue
		}
		ms.Contents = slices.DeleteFunc(ms.Contents, func(kv ebpf.MapKV) bool {
			name, ok := kv.Value.(string)
			return ok && slices.Contains(dropped, name)
		})
	}
}

func hasRodataConfigMap(spec *ebpf.CollectionSpec) bool {
	for name := range spec.Maps {
		if _, ok := lookupRodataConfigMap(name); ok {
			return true
		}
	}
	return false
}
