// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon
package alignchecker

import (
	"reflect"

	"github.com/cilium/tetragon/pkg/api/confapi"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/api/testapi"
	"github.com/cilium/tetragon/pkg/api/tracingapi"
	"github.com/cilium/tetragon/pkg/sensors/cgroup/cgrouptrackmap"
	"github.com/cilium/tetragon/pkg/sensors/config/confmap"
	"github.com/cilium/tetragon/pkg/sensors/exec/execvemap"

	check "github.com/cilium/cilium/pkg/alignchecker"
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
func CheckStructAlignments(path string) error {
	// Validate alignments of C and Go equivalent structs
	toCheck := map[string][]reflect.Type{
		// from perf_event_output
		"msg_exit":              {reflect.TypeOf(processapi.MsgExitEvent{})},
		"msg_test":              {reflect.TypeOf(testapi.MsgTestEvent{})},
		"msg_execve_key":        {reflect.TypeOf(processapi.MsgExecveKey{})},
		"execve_map_value":      {reflect.TypeOf(execvemap.ExecveValue{})},
		"event_config":          {reflect.TypeOf(tracingapi.EventConfig{})},
		"tetragon_conf":         {reflect.TypeOf(confapi.TetragonConf{})},
		"cgroup_tracking_value": {reflect.TypeOf(processapi.MsgCgroupData{})},
		"msg_cgroup_event":      {reflect.TypeOf(processapi.MsgCgroupEvent{})},
	}

	confMap := map[string][]reflect.Type{
		"tetragon_conf": {reflect.TypeOf(confmap.TetragonConfValue{})},
	}

	cgrpmap := map[string][]reflect.Type{
		"cgroup_tracking_value": {reflect.TypeOf(cgrouptrackmap.CgrpTrackingValue{})},
	}

	err := check.CheckStructAlignments(path, toCheck, true)
	if err != nil {
		return err
	}

	err = check.CheckStructAlignments(path, confMap, true)
	if err != nil {
		return err
	}

	return check.CheckStructAlignments(path, cgrpmap, true)
}
