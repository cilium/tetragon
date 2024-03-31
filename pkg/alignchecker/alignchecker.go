// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package alignchecker

import (
	"github.com/cilium/cilium/pkg/alignchecker"

	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/api/testapi"
	"github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/sensors/cgroup/cgrouptrackmap"
	"github.com/cilium/tetragon/pkg/sensors/config/confmap"
	"github.com/cilium/tetragon/pkg/sensors/exec/execvemap"
)

// CheckStructAlignments checks whether size and offsets of the C and Go
// structs for the datapath match.
//
// C struct size info is extracted from the given ELF object file debug section
// encoded in DWARF.
//
// To find a matching C struct field, a Go field has to be tagged with
// `align:"field_name_in_c_struct". In the case of unnamed union field, such
// union fields can be referred with special tags - `align:"$union0"`,
// `align:"$union1"`, etc.
func CheckStructAlignments(pathToObj string) error {
	alignments := map[string][]any{
		// from perf_event_output
		"msg_exit":         {processapi.MsgExitEvent{}},
		"msg_test":         {testapi.MsgTestEvent{}},
		"msg_execve_key":   {processapi.MsgExecveKey{}},
		"execve_map_value": {execvemap.ExecveValue{}},
		"msg_cgroup_event": {processapi.MsgCgroupEvent{}},
		"msg_cred":         {processapi.MsgGenericCred{}},

		// configuration
		"event_config":  {tracingapi.EventConfig{}},
		"tetragon_conf": {confmap.TetragonConfValue{}},

		// cgroup
		"cgroup_tracking_value": {cgrouptrackmap.CgrpTrackingValue{}},

		// metrics
		"kernel_stats": {processapi.KernelStats{}},
	}

	return alignchecker.CheckStructAlignments(pathToObj, alignments, true)
}
